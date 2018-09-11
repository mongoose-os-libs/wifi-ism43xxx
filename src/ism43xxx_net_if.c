/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Mongoose net_if impl */

#include "mgos.h"

#include "ism43xxx_core.h"

struct ism43xxx_socket_ctx {
  struct mg_connection *nc;
  const struct ism43xxx_cmd *cur_seq;
  struct mbuf rx_buf;
  struct mbuf tx_buf;
};

struct ism43xxx_if_ctx {
  struct ism43xxx_ctx *ism_ctx;
  const struct ism43xxx_cmd *cur_poll_seq;
  struct ism43xxx_socket_ctx sockets[ISM43XXX_AP_MAX_SOCKETS];
};

static void ism43xxx_core_disconnect(void *arg);
static void ism43xxx_core_data_poll(void *arg);

static bool ism43xxx_socket_send_seq(struct ism43xxx_socket_ctx *sctx,
                                     const struct ism43xxx_cmd *seq,
                                     bool copy) {
  struct ism43xxx_if_ctx *ctx =
      (struct ism43xxx_if_ctx *) sctx->nc->iface->data;
  if (sctx->cur_seq != NULL) {
    ism43xxx_abort_seq(ctx->ism_ctx, &sctx->cur_seq);
  }
  sctx->cur_seq = ism43xxx_send_seq(ctx->ism_ctx, seq, copy);
  if (sctx->cur_seq == NULL) {
    sctx->nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    return false;
  }
  return true;
}

static void ism43xxx_socket_assign(struct ism43xxx_if_ctx *ctx,
                                   struct mg_connection *nc, int i) {
  char buf1[16];
  struct ism43xxx_socket_ctx *sctx = &ctx->sockets[i];
  LOG(LL_DEBUG,
      ("%p %s:%u %s assigned sock %d", nc,
       mgos_net_ip_to_str(&nc->sa.sin, buf1), htons(nc->sa.sin.sin_port),
       ((nc->flags & MG_F_UDP) ? "UDP" : "TCP"), i));
  nc->sock = i;
  sctx->nc = nc;
}

/* Verify that the sequence that completed was not superseded. */
static bool ism43xxx_socket_verify_seq(struct ism43xxx_socket_ctx *sctx,
                                       const struct ism43xxx_cmd *cmd) {
  const struct ism43xxx_cmd *c = sctx->cur_seq;
  if (c == NULL) return false;
  while (c->cmd != NULL) {
    if (c == cmd) return true;
    c++;
  }
  return (c == cmd);
}

static bool close_seq_done_cb(struct ism43xxx_ctx *c,
                              const struct ism43xxx_cmd *cmd, bool ok,
                              struct mg_str p) {
  struct ism43xxx_socket_ctx *sctx =
      (struct ism43xxx_socket_ctx *) cmd->user_data;
  if (!ism43xxx_socket_verify_seq(sctx, cmd)) return true;
  sctx->cur_seq = NULL;
  /* Nothing further to do. */
  (void) c;
  (void) ok;
  (void) p;
  return true;
}

static bool ism43xxx_socket_close(struct ism43xxx_socket_ctx *sctx, int i) {
  const struct ism43xxx_cmd client_close_seq[] = {
      {.cmd = asp("P0=%d", i), .free = true},
      {.cmd = "P6=0"},
      {.cmd = NULL, .ph = close_seq_done_cb, .user_data = sctx},
  };
  return ism43xxx_socket_send_seq(sctx, client_close_seq, true /* copy */);
}

static bool ism43xxx_socket_find_free(struct ism43xxx_if_ctx *ctx,
                                      struct mg_connection *nc) {
  if (ctx->ism_ctx == NULL) {
    ctx->ism_ctx = ism43xxx_get_ctx();
    if (ctx->ism_ctx == NULL) {
      LOG(LL_ERROR, ("Wifi not active"));
      return false;
    }
    ctx->ism_ctx->if_data_poll_cb = ism43xxx_core_data_poll;
    ctx->ism_ctx->if_disconnect_cb = ism43xxx_core_disconnect;
    ctx->ism_ctx->if_cb_arg = ctx;
  }
  if (ctx->ism_ctx->mode == ISM43XXX_MODE_STA && !ctx->ism_ctx->sta_connected) {
    return false;
  }
  if ((nc->flags & MG_F_UDP)) {
    for (int i = 0; i < (int) ARRAY_SIZE(ctx->sockets); i++) {
      struct ism43xxx_socket_ctx *sctx = &ctx->sockets[i];
      /* Do not allow multiple active UDP sockets with the same destination
       * port. This is because of a bug in the current firmware (C3.5.2.3.BETA9)
       * which sets src port to be equal to dst. This actually works but causes
       * replies to be mixed up. */
      if (sctx->nc != NULL &&
          sctx->nc->sa.sin.sin_port == nc->sa.sin.sin_port) {
        return false;
      }
    }
  }
  for (int i = 0; i < (int) ARRAY_SIZE(ctx->sockets); i++) {
    struct ism43xxx_socket_ctx *sctx = &ctx->sockets[i];
    if (sctx->cur_seq == NULL &&
        (sctx->nc == NULL || (sctx->nc->flags & MG_F_CLOSE_IMMEDIATELY))) {
      ism43xxx_socket_assign(ctx, nc, i);
      return true;
    }
  }
  LOG(LL_ERROR, ("No sockets available! (max %d)", ISM43XXX_AP_MAX_SOCKETS));
  nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  return false;
}

static bool connect_seq_done_cb(struct ism43xxx_ctx *c,
                                const struct ism43xxx_cmd *cmd, bool ok,
                                struct mg_str p) {
  struct ism43xxx_socket_ctx *sctx =
      (struct ism43xxx_socket_ctx *) cmd->user_data;
  if (!ism43xxx_socket_verify_seq(sctx, cmd)) return true;
  sctx->cur_seq = NULL;
  struct mg_connection *nc = sctx->nc;
  if (nc != NULL) mg_if_connect_cb(nc, (ok ? 0 : -1));
  (void) c;
  (void) p;
  return true;
}

static void ism43xxx_if_connect(struct mg_connection *nc, int proto,
                                int max_read_size) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) nc->iface->data;
  if (!ism43xxx_socket_find_free(ctx, nc)) {
    if ((nc->flags & MG_F_UDP)) {
      /* UDP will be retried, assumption being that they are transient. */
    } else {
      mg_if_connect_cb(nc, -2);
    }
    return;
  }
  char addr_buf[16];
  struct ism43xxx_socket_ctx *sctx = &ctx->sockets[nc->sock];
  const struct ism43xxx_cmd udp_client_setup_seq[] = {
      {.cmd = asp("P0=%d", nc->sock), .free = true},
      {.cmd = asp("P1=%d", proto), .free = true},
      {.cmd = asp("P3=%s", mgos_net_ip_to_str(&nc->sa.sin, addr_buf)),
       .free = true},
      {.cmd = asp("P4=%u", ntohs(nc->sa.sin.sin_port)), .free = true},
      {.cmd = asp("R1=%d", max_read_size), .free = true},
      {.cmd = "R2=200"}, /* Non-blocking reads */
      {.cmd = "S2=500"}, /* Allow 500 ms to send a packet */
      {.cmd = "R3=0"},   /* Do not remove CRLF from data */
      {.cmd = "P6=1"},   /* Start client */
      {.cmd = NULL, .ph = connect_seq_done_cb, .user_data = sctx},
  };
  if (!ism43xxx_socket_send_seq(sctx, udp_client_setup_seq, true /* copy */)) {
    mg_if_connect_cb(nc, -4);
  }
}

static void ism43xxx_if_connect_tcp(struct mg_connection *nc,
                                    const union socket_address *sa) {
  (void) sa;
  ism43xxx_if_connect(nc, 0 /* TCP */, ISM43XXX_MAX_TCP_IO_SIZE);
}

static void ism43xxx_if_connect_udp(struct mg_connection *nc) {
  ism43xxx_if_connect(nc, 1 /* UDP */, ISM43XXX_MAX_UDP_IO_SIZE);
}

static int ism43xxx_if_listen_tcp(struct mg_connection *nc,
                                  union socket_address *sa) {
  /*
   * XXX: We pretend listen succeeded but don't actually do anything.
   * TODO(rojer): Implement.
   */
  (void) nc;
  (void) sa;
  return 0;
}

static int ism43xxx_if_listen_udp(struct mg_connection *nc,
                                  union socket_address *sa) {
  (void) nc;
  (void) sa;
  return -1;
}

static bool data_send_done_cb(struct ism43xxx_ctx *c,
                              const struct ism43xxx_cmd *cmd, bool ok,
                              struct mg_str p) {
  struct ism43xxx_socket_ctx *sctx =
      (struct ism43xxx_socket_ctx *) cmd->user_data;
  if (!ism43xxx_socket_verify_seq(sctx, cmd)) return true;
  sctx->cur_seq = NULL;
  ok = ok && (p.p[0] != '-');
  if (ok) {
    LOG(LL_DEBUG,
        ("%p %d -> %d", sctx->nc, sctx->nc->sock, (int) sctx->tx_buf.len));
    // mg_hexdumpf(stderr, sctx->tx_buf.buf, sctx->tx_buf.len);
    mbuf_free(&sctx->tx_buf);
    mbuf_init(&sctx->tx_buf, 0);
  }
  (void) c;
  return true;
}

static bool ism43xxx_if_send_data(struct ism43xxx_socket_ctx *sctx) {
  if (sctx->cur_seq != NULL || sctx->tx_buf.len == 0) return 0;
  struct mg_connection *nc = sctx->nc;
  size_t len = sctx->tx_buf.len;
  const struct ism43xxx_cmd send_seq[] = {
      {.cmd = asp("P0=%d", nc->sock), .free = true},
      {.cmd = asp("S3=%d\r", (int) len), .free = true, .cont = true},
      {.cmd = sctx->tx_buf.buf,
       .len = len,
       .free = false,
       .ph = data_send_done_cb,
       .user_data = sctx},
      {.cmd = NULL},
  };
  return ism43xxx_socket_send_seq(sctx, send_seq, true /* copy */);
}

static int ism43xxx_if_send(struct mg_connection *nc, const void *buf,
                            size_t len) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) nc->iface->data;
  struct ism43xxx_socket_ctx *sctx = &ctx->sockets[nc->sock];
  if (sctx->cur_seq != NULL || sctx->tx_buf.len > 0) return 0;
  mbuf_append(&sctx->tx_buf, buf, len);
  if (sctx->tx_buf.len != len) return -2;
  return (ism43xxx_if_send_data(sctx) ? (int) len : -1);
}

static int ism43xxx_if_tcp_send(struct mg_connection *nc, const void *buf,
                                size_t len) {
  return ism43xxx_if_send(nc, buf, MIN(len, ISM43XXX_MAX_TCP_IO_SIZE));
}

static int ism43xxx_if_udp_send(struct mg_connection *nc, const void *buf,
                                size_t len) {
  return ism43xxx_if_send(nc, buf, MIN(len, ISM43XXX_MAX_UDP_IO_SIZE));
}

int ism43xxx_if_tcp_recv(struct mg_connection *nc, void *buf, size_t len) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) nc->iface->data;
  if (nc->sock == INVALID_SOCKET) return -1;
  struct ism43xxx_socket_ctx *sctx = &ctx->sockets[nc->sock];
  len = MIN(len, sctx->rx_buf.len);
  if (len > 0) {
    memcpy(buf, sctx->rx_buf.buf, len);
    mbuf_remove(&sctx->rx_buf, len);
    mbuf_trim(&sctx->rx_buf);
    LOG(LL_DEBUG, ("%p %d <- %d", nc, nc->sock, (int) len));
    // mg_hexdumpf(stderr, buf, len);
  }
  return len;
}

int ism43xxx_if_udp_recv(struct mg_connection *nc, void *buf, size_t len,
                         union socket_address *sa, size_t *sa_len) {
  memset(sa, 0, *sa_len);
  if (nc->flags & MG_F_LISTENING) {
    /* XXX: How to get source addr? */
  } else {
    /* Data is coming from the peer, obviosuly. */
    *sa = nc->sa;
  }
  return ism43xxx_if_tcp_recv(nc, buf, len);
}

static int ism43xxx_if_create_conn(struct mg_connection *nc) {
  (void) nc;
  return 1;
}

static void ism43xxx_if_destroy_conn(struct mg_connection *nc) {
  (void) nc;
}

static void ism43xxx_if_sock_set(struct mg_connection *c, sock_t sock) {
  (void) c;
  (void) sock;
}

static void ism43xxx_if_init(struct mg_iface *iface) {
  struct ism43xxx_if_ctx *ctx =
      (struct ism43xxx_if_ctx *) calloc(1, sizeof(*ctx));
  for (int i = 0; i < (int) ARRAY_SIZE(ctx->sockets); i++) {
    mbuf_init(&ctx->sockets[i].rx_buf, 0);
    mbuf_init(&ctx->sockets[i].tx_buf, 0);
  }
  iface->data = ctx;
}

static void ism43xxx_if_free(struct mg_iface *iface) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) iface->data;
  iface->data = NULL;
  if (ctx->ism_ctx != NULL) {
    ctx->ism_ctx->if_data_poll_cb = NULL;
    ctx->ism_ctx->if_disconnect_cb = NULL;
    ctx->ism_ctx->if_cb_arg = NULL;
  }
  free(ctx);
}

static void ism43xxx_if_add_conn(struct mg_connection *nc) {
  (void) nc;
}

static void ism43xxx_if_remove_conn(struct mg_connection *nc) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) nc->iface->data;
  int sock = nc->sock;
  if (sock == INVALID_SOCKET || ctx->sockets[sock].nc != nc) return;
  struct ism43xxx_socket_ctx *sctx = &ctx->sockets[nc->sock];
  LOG(LL_DEBUG, ("%p released sock %d", nc, sock));
  ism43xxx_socket_close(sctx, sock);
  sctx->nc = NULL;
  nc->sock = INVALID_SOCKET;
  mbuf_free(&sctx->rx_buf);
  mbuf_free(&sctx->tx_buf);
}

static bool ism43xxx_r0_cb(struct ism43xxx_ctx *c,
                           const struct ism43xxx_cmd *cmd, bool ok,
                           struct mg_str p) {
  if (!ok) return true;
  struct ism43xxx_socket_ctx *sctx =
      (struct ism43xxx_socket_ctx *) cmd->user_data;
  struct mg_connection *nc = sctx->nc;
  if (nc == NULL) return true;
  p = ism43xxx_process_async_ev(c, p);
  if (p.len > 0) {
    p.len -= 2; /* \r\n at the end */
                /* And if legitimate data packet happens to be "-1"?
                 * Well, sucks to be you then, I guess. */
    if (p.len == 2 && mg_vcmp(&p, "-1") == 0) {
      LOG(LL_ERROR, ("%p %d read error", nc, nc->sock));
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      return true;
    }
    LOG(LL_DEBUG, ("<- %d", (int) p.len));
    // mg_hexdumpf(stderr, p.p, p.len);
    mbuf_append(&sctx->rx_buf, p.p, p.len);
    mg_if_can_recv_cb(nc);
  }
  return true;
}

static bool ism43xxx_poll_done(struct ism43xxx_ctx *c,
                               const struct ism43xxx_cmd *cmd, bool ok,
                               struct mg_str p) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) cmd->user_data;
  ctx->cur_poll_seq = NULL;
  (void) c;
  (void) ok;
  (void) p;
  return true;
}

static void ism43xxx_core_disconnect(void *arg) {
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) arg;
  LOG(LL_DEBUG, ("disconnect"));
  for (int i = 0; i < (int) ARRAY_SIZE(ctx->sockets); i++) {
    struct ism43xxx_socket_ctx *sctx = &ctx->sockets[i];
    if (sctx->nc == NULL) continue;
    sctx->nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    sctx->nc->sock = INVALID_SOCKET;
    sctx->cur_seq = NULL;
    sctx->nc = NULL;
  }
}

static void ism43xxx_core_data_poll(void *arg) {
  // LOG(LL_DEBUG, ("data poll"));
  struct ism43xxx_cmd *cmd;
  struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) arg;
  struct ism43xxx_cmd *poll_seq = (struct ism43xxx_cmd *) calloc(
      (ARRAY_SIZE(ctx->sockets) * 2) + 1, sizeof(*poll_seq));
  if (poll_seq == NULL) return;
  int j = 0;
  for (int i = 0; i < (int) ARRAY_SIZE(ctx->sockets); i++) {
    struct ism43xxx_socket_ctx *sctx = &ctx->sockets[i];
    if (sctx->nc == NULL) continue;
    if (sctx->nc->flags & MG_F_LISTENING) {
      /* TODO(rojer) */
    } else if ((sctx->nc->flags & (MG_F_CONNECTING | MG_F_CLOSE_IMMEDIATELY)) ==
               0) {
      cmd = &poll_seq[j++];
      cmd->cmd = asp("P0=%d", i);
      cmd->free = true;
      cmd = &poll_seq[j++];
      cmd->cmd = "R0";
      cmd->ph = ism43xxx_r0_cb;
      cmd->user_data = sctx;
    }
  }
  if (j > 0) {
    cmd = &poll_seq[j++];
    cmd->free = true;
    cmd->ph = ism43xxx_poll_done;
    cmd->user_data = ctx;
    ctx->cur_poll_seq =
        ism43xxx_send_seq(ctx->ism_ctx, poll_seq, false /* copy */);
    if (ctx->cur_poll_seq == NULL) {
      free(poll_seq);
    }
  } else {
    free(poll_seq);
  }
}

static time_t ism43xxx_if_poll(struct mg_iface *iface, int timeout_ms) {
  struct mg_mgr *mgr = iface->mgr;
  struct mg_connection *nc, *tmp;
  double now = mg_time();
  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;
    if (nc->iface != iface) continue;
    mg_if_poll(nc, now);
    if (nc->sock != INVALID_SOCKET) {
      struct ism43xxx_if_ctx *ctx = (struct ism43xxx_if_ctx *) nc->iface->data;
      struct ism43xxx_socket_ctx *sctx = &ctx->sockets[nc->sock];
      if (sctx->tx_buf.len == 0) {
        mg_if_can_send_cb(nc);
      } else {
        ism43xxx_if_send_data(sctx);
      }
    } else if (!(nc->flags & MG_F_CLOSE_IMMEDIATELY)) {
      /* Retry pending UDP connections. */
      if ((nc->flags & MG_F_UDP) && (nc->flags & MG_F_CONNECTING)) {
        ism43xxx_if_connect_udp(nc);
      }
    }
  }
  (void) timeout_ms;
  return (time_t) now;
}

static void ism43xxx_if_get_conn_addr(struct mg_connection *c, int remote,
                                      union socket_address *sa) {
  (void) c;
  (void) remote;
  (void) sa;
}

#define ISM43XXX_IFACE_VTABLE                                                \
  {                                                                          \
    ism43xxx_if_init, ism43xxx_if_free, ism43xxx_if_add_conn,                \
        ism43xxx_if_remove_conn, ism43xxx_if_poll, ism43xxx_if_listen_tcp,   \
        ism43xxx_if_listen_udp, ism43xxx_if_connect_tcp,                     \
        ism43xxx_if_connect_udp, ism43xxx_if_tcp_send, ism43xxx_if_udp_send, \
        ism43xxx_if_tcp_recv, ism43xxx_if_udp_recv, ism43xxx_if_create_conn, \
        ism43xxx_if_destroy_conn, ism43xxx_if_sock_set,                      \
        ism43xxx_if_get_conn_addr,                                           \
  }

/* LwIP must be disabled for this to work.
 * This kinda smells, but will do for now. */
const struct mg_iface_vtable mg_default_iface_vtable = ISM43XXX_IFACE_VTABLE;
