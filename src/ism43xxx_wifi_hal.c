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

/* WiFi HAL API impl */

#include "mgos.h"
#include "mgos_wifi_hal.h"

#include "ism43xxx_core.h"

#define ISM43XXX_LINE_SEP "\r\n"

struct ism43xxx_ctx *s_ctx = NULL;

static char *asp(const char *fmt, ...) PRINTF_LIKE(1, 2);
static char *asp(const char *fmt, ...) {
  char *res = NULL;
  va_list ap;
  va_start(ap, fmt);
  mg_avprintf(&res, 0, fmt, ap);
  va_end(ap);
  return res;
}

/* AP */

bool ism43xxx_parse_mac(const char *s, uint8_t mac[6]) {
  unsigned int m0, m1, m2, m3, m4, m5;
  if (sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X", &m0, &m1, &m2, &m3, &m4,
             &m5) != 6) {
    return false;
  }
  mac[0] = m0;
  mac[1] = m1;
  mac[2] = m2;
  mac[3] = m3;
  mac[4] = m4;
  mac[5] = m5;
  return true;
}

static bool ism43xxx_ar_cb(struct ism43xxx_ctx *c, bool ok,
                           const struct mg_str payload) {
  int n = 0;
  struct ism43xxx_client_info ap_clients[ISM43XXX_AP_MAX_CLIENTS];
  const struct mg_str sep = mg_mk_str(ISM43XXX_LINE_SEP);
  if (!ok) return false;
  /* Mark clients that are still connected. */
  int gen = 0;
  for (int i = 0; i < ARRAY_SIZE(c->ap_clients); i++) {
    gen = MAX(gen, c->ap_clients[i].gen);
  }
  if (++gen == 0) ++gen;
  const char *eol;
  struct mg_str buf = payload;
  while ((eol = mg_strstr(buf, sep)) != NULL && n < ISM43XXX_AP_MAX_CLIENTS) {
    struct mg_str s;
    struct mg_str e = mg_mk_str_n(buf.p, eol - buf.p);
    struct ism43xxx_client_info *ci = &ap_clients[n];
    buf.p += e.len + sep.len;
    buf.len -= e.len + sep.len;
    e = mg_next_comma_list_entry_n(e, &s, NULL); /* Index, skip */
    e = mg_next_comma_list_entry_n(e, &s, NULL); /* MAC */
    if (s.p == NULL || !ism43xxx_parse_mac(s.p, ci->mac)) continue;
    e = mg_next_comma_list_entry_n(e, &s, NULL); /* MAC */
    if (s.p == NULL) continue;
    ci->rssi = strtol(s.p, NULL, 10);
    if (ci->rssi >= 0) continue;
    ci->gen = gen;
    for (int i = 0; i < ARRAY_SIZE(c->ap_clients); i++) {
      if (memcmp(c->ap_clients[i].mac, ap_clients[n].mac,
                 sizeof(ap_clients[n].mac)) == 0) {
        c->ap_clients[i].rssi = ci->rssi;
        c->ap_clients[i].gen = gen;
        ci->gen = 0;
        break;
      }
    }
    if (ci->gen != 0) n++;
  }
  /* Sweep away clients that are gone. */
  for (int i = 0; i < ARRAY_SIZE(c->ap_clients); i++) {
    struct ism43xxx_client_info *ci = &c->ap_clients[i];
    if (ci->gen == 0 || ci->gen == gen) continue;
    struct mgos_wifi_ap_sta_disconnected_arg arg;
    memset(&arg, 0, sizeof(arg));
    memcpy(arg.mac, ci->mac, sizeof(arg.mac));
    mgos_wifi_dev_on_change_cb(MGOS_WIFI_EV_AP_STA_DISCONNECTED, &arg);
    memset(&c->ap_clients[i], 0, sizeof(c->ap_clients[i]));
  }
  /* Add new clients */
  for (int i = 0; i < n; i++) {
    struct ism43xxx_client_info *ci = &ap_clients[i];
    for (int j = 0; i < ARRAY_SIZE(c->ap_clients); j++) {
      if (c->ap_clients[j].gen == 0) {
        memcpy(&c->ap_clients[j], ci, sizeof(c->ap_clients[j]));
        struct mgos_wifi_ap_sta_connected_arg arg;
        memset(&arg, 0, sizeof(arg));
        memcpy(arg.mac, ci->mac, sizeof(arg.mac));
        mgos_wifi_dev_on_change_cb(MGOS_WIFI_EV_AP_STA_CONNECTED, &arg);
        break;
      }
    }
  }

  return ok;
}

static bool ism43xxx_pre_ad_cb(struct ism43xxx_ctx *c, bool ok,
                               struct mg_str p) {
  LOG(LL_INFO, ("AP starting..."));
  (void) c;
  (void) p;
  return ok;
}

static bool ism43xxx_ad_cb(struct ism43xxx_ctx *c, bool ok,
                           struct mg_str payload) {
  if (ok) {
    LOG(LL_INFO, ("AP started"));
  } else {
    LOG(LL_INFO, ("AP failed to start: %.*s", (int) payload.len, payload.p));
  }
  return ok;
}

const struct ism43xxx_cmd ism43xxx_ap_poll_seq[] = {
    {.cmd = "AR", .ph = ism43xxx_ar_cb},
    {.cmd = "MR", .ph = ism43xxx_mr_cb},
    {.cmd = NULL},
};

bool mgos_wifi_dev_ap_setup(const struct mgos_config_wifi_ap *cfg) {
  bool res = false;
  struct ism43xxx_ctx *c = s_ctx;

  if (!cfg->enable) {
    if (c->mode == ISM43XXX_MODE_AP) {
      ism43xxx_reset(s_ctx, true /* hold */);
    }
    res = true;
    goto out;
  }

  int max_clients = MIN(cfg->max_connections, ISM43XXX_AP_MAX_CLIENTS);

  const struct ism43xxx_cmd ism43xxx_ap_setup_seq[] = {
      /* Disable STA and AP, if enabled, to start with a clean slate. */
      {.cmd = "CD", .ph = ism43xxx_ignore_error},
      {.cmd = "AE", .ph = ism43xxx_ignore_error},
      /* SSID */
      {.cmd = asp("AS=0,%s", cfg->ssid), .free_cmd = true},
      /* Security (0 = open, 3 = WPA2) */
      {.cmd = (cfg->pass ? "A1=3" : "A1=0")},
      /* Password */
      {.cmd = asp("A2=%s", (cfg->pass ? cfg->pass : "")), .free_cmd = true},
      /* Channel; 0 = auto */
      {.cmd = asp("AC=%d", cfg->channel), .free_cmd = true},
      /* Max num clients */
      {.cmd = asp("AT=%d", max_clients), .free_cmd = true},
      /* AP's IP address. Netmask is not configurable. */
      {.cmd = asp("Z6=%s", cfg->ip), .free_cmd = true},
      /* No power saving */
      {.cmd = "ZP=0", .ph = ism43xxx_pre_ad_cb},
      /* Activate */
      {.cmd = "AD", .ph = ism43xxx_ad_cb, .timeout = 10},
      {.cmd = NULL},
  };

  if (c->phase == ISM43XXX_PHASE_CMD && c->mode == ISM43XXX_MODE_IDLE) {
    ism43xxx_send_cmd_seq(c, ism43xxx_ap_setup_seq, true /* copy */);
  } else {
    ism43xxx_reset(c, false /* hold */);
    ism43xxx_send_cmd_seq(c, ism43xxx_ap_setup_seq, true /* copy */);
  }

  c->mode = ISM43XXX_MODE_AP;

  res = true;

out:
  return res;
}

/* STA */

void ism43xxx_set_sta_status(struct ism43xxx_ctx *c, bool connected,
                             bool force) {
  if (connected != c->sta_connected || force) {
    c->sta_connected = connected;
    if (connected) {
      mgos_wifi_dev_on_change_cb(MGOS_WIFI_EV_STA_CONNECTED, NULL);
      if (c->sta_ip_info.ip.sin_addr.s_addr != 0) {
        mgos_wifi_dev_on_change_cb(MGOS_WIFI_EV_STA_IP_ACQUIRED, NULL);
      }
    } else {
      mgos_wifi_dev_on_change_cb(MGOS_WIFI_EV_STA_DISCONNECTED, NULL);
    }
  }
}

static bool ism43xxx_pre_c0_cb(struct ism43xxx_ctx *c, bool ok,
                               struct mg_str p) {
  LOG(LL_INFO, ("STA connecting..."));
  (void) c;
  (void) p;
  return true;
}

static bool ism43xxx_c0_cb(struct ism43xxx_ctx *c, bool ok, struct mg_str p) {
  /* Suppress the error to prevent automated replay.
   * CS will report disconnection and upper layer will re-connect. */
  return true;
}

static bool ism43xxx_cr_cb(struct ism43xxx_ctx *c, bool ok, struct mg_str p) {
  c->sta_rssi = (ok ? strtol(p.p, NULL, 10) : 0);
  return true;
}

static bool ism43xxx_cinfo_cb(struct ism43xxx_ctx *c, bool ok,
                              struct mg_str p) {
  struct mg_str s = mg_strstrip(p), ip, nm, gw, dns, status, unused;
  bool sta_connected = false;
  if (ok) {
    memset(&c->sta_ip_info, 0, sizeof(c->sta_ip_info));
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* SSID */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Pass */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Security type */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* DHCP on/off */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* IP ver */
    s = mg_next_comma_list_entry_n(s, &ip, NULL);
    s = mg_next_comma_list_entry_n(s, &nm, NULL);
    s = mg_next_comma_list_entry_n(s, &gw, NULL);
    s = mg_next_comma_list_entry_n(s, &dns, NULL);
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* DNS2 */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Num retries */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Autoconnect */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Authentication (?) */
    s = mg_next_comma_list_entry_n(s, &unused, NULL); /* Country */
    s = mg_next_comma_list_entry_n(s, &status, NULL);
    sta_connected = (status.len == 1 && status.p[0] == '1');
    if (sta_connected) {
      if (ip.len > 0 && nm.len > 0 && gw.len > 0) {
        mgos_net_str_to_ip_n(ip, &c->sta_ip_info.ip);
        mgos_net_str_to_ip_n(nm, &c->sta_ip_info.netmask);
        mgos_net_str_to_ip_n(gw, &c->sta_ip_info.gw);
      }
      if (dns.len > 3) {
        /* FW versions prior to 3.5.2.4 do not set the DNS server field. */
        struct mg_str dnsp = mg_mk_str_n(dns.p, 3);
        if (mg_vcmp(&dnsp, "255") == 0) {
          LOG(LL_WARN, ("BUG: DNS is not set, using default. "
                        "Please Update the es-WiFi module FW."));
        } else {
        }
      }
    }
  }
  ism43xxx_set_sta_status(c, sta_connected, true /* force */);
  return true;
}

static bool ism43xxx_cs_cb(struct ism43xxx_ctx *c, bool ok, struct mg_str p) {
  if (ok) {
    bool sta_connected = (p.p[0] == '1');
    ism43xxx_set_sta_status(c, sta_connected, false /* force */);
  }
  return ok;
}

static bool ism43xxx_cd_cb(struct ism43xxx_ctx *c, bool ok,
                           struct mg_str payload) {
  if (ok) {
    ism43xxx_set_sta_status(c, false /* connected */, false /* force */);
  }
  return ok;
}

const struct ism43xxx_cmd ism43xxx_sta_connect_seq[] = {
    {.cmd = "C?", .ph = ism43xxx_pre_c0_cb},
    {.cmd = "C0", .ph = ism43xxx_c0_cb, .timeout = 20},
    {.cmd = "CR", .ph = ism43xxx_cr_cb}, /* Get RSSI */
    {.cmd = "C?", .ph = ism43xxx_cinfo_cb},
    {.cmd = NULL},
};

const struct ism43xxx_cmd ism43xxx_sta_disconnect_seq[] = {
    {.cmd = "CD", .ph = ism43xxx_cd_cb}, {.cmd = NULL},
};

const struct ism43xxx_cmd ism43xxx_sta_poll_seq[] = {
    {.cmd = "CR", .ph = ism43xxx_cr_cb},
    {.cmd = "CS", .ph = ism43xxx_cs_cb},
    {.cmd = "MR", .ph = ism43xxx_mr_cb},
    {.cmd = NULL},
};

bool mgos_wifi_dev_sta_setup(const struct mgos_config_wifi_sta *cfg) {
  bool res = false;
  struct ism43xxx_ctx *c = s_ctx;

  if (!cfg->enable) {
    if (c->mode == ISM43XXX_MODE_STA) {
      ism43xxx_reset(s_ctx, true /* hold */);
    }
    res = true;
    goto out;
  }

  bool static_ip = (cfg->ip != NULL && cfg->netmask != NULL);

  const struct ism43xxx_cmd ism43xxx_sta_setup_seq[] = {
      /* Disable STA and AP, if enabled, to start with a clean slate. */
      {.cmd = "CD", .ph = ism43xxx_ignore_error},
      {.cmd = "AE", .ph = ism43xxx_ignore_error},
      {.cmd = asp("C1=%s", cfg->ssid), .free_cmd = true},
      {.cmd = asp("C2=%s", (cfg->pass ? cfg->pass : "")), .free_cmd = true},
      /* Security (0 = open, 4 = WPA+WPA2) */
      {.cmd = (cfg->pass != NULL ? "C3=4" : "C3=0")},
      /* DHCP (1 = on, 0 = off, use static IP) */
      {.cmd = (static_ip ? "C4=0" : "C4=1")},
      {.cmd = asp("C6=%s", (cfg->ip ? cfg->ip : "0.0.0.0")), .free_cmd = true},
      {.cmd = asp("C7=%s", (cfg->netmask ? cfg->netmask : "0.0.0.0")),
       .free_cmd = true},
      {.cmd = asp("C8=%s", (cfg->gw ? cfg->gw : "0.0.0.0")), .free_cmd = true},
      /* 0 = IPv4, 1 = IPv6 */
      {.cmd = "C5=0"},
      /* Retry count - try once. Reconnects will be handled by higher layers. */
      {.cmd = "CB=1"},
      {.cmd = NULL},
  };

  if (c->phase == ISM43XXX_PHASE_CMD && c->mode == ISM43XXX_MODE_IDLE) {
    ism43xxx_send_cmd_seq(c, ism43xxx_sta_setup_seq, true /* copy */);
  } else {
    ism43xxx_reset(c, false /* hold */);
    ism43xxx_send_cmd_seq(c, ism43xxx_sta_setup_seq, true /* copy */);
  }

  c->mode = ISM43XXX_MODE_STA;

  res = true;

out:
  return res;
}

bool mgos_wifi_dev_sta_connect(void) {
  struct ism43xxx_ctx *c = (struct ism43xxx_ctx *) s_ctx;
  if (c->mode != ISM43XXX_MODE_STA) return false;
  ism43xxx_send_cmd_seq(c, ism43xxx_sta_connect_seq, false /* copy */);
  return true;
}

bool mgos_wifi_dev_sta_disconnect(void) {
  struct ism43xxx_ctx *c = (struct ism43xxx_ctx *) s_ctx;
  if (c->mode != ISM43XXX_MODE_STA) return false;
  ism43xxx_send_cmd_seq(c, ism43xxx_sta_disconnect_seq, false /* copy */);
  return true;
}

char *mgos_wifi_get_connected_ssid(void) {
  return strdup("TODO(rojer)");
}

bool mgos_wifi_dev_get_ip_info(int if_instance,
                               struct mgos_net_ip_info *ip_info) {
  struct ism43xxx_ctx *c = (struct ism43xxx_ctx *) s_ctx;
  bool res = false;
  if (if_instance == 0) {
    memcpy(ip_info, &c->sta_ip_info, sizeof(*ip_info));
    res = true;
  } else if (if_instance == 1) {
    memcpy(ip_info, &c->ap_ip_info, sizeof(*ip_info));
    res = true;
  } else {
    memset(ip_info, 0, sizeof(*ip_info));
  }
  return res;
}

char *mgos_wifi_get_sta_default_dns(void) {
  /* I don't think this is even possible... */
  return NULL;
}

int mgos_wifi_sta_get_rssi(void) {
  struct ism43xxx_ctx *c = (struct ism43xxx_ctx *) s_ctx;
  return c->sta_rssi;
}

void mgos_wifi_dev_init(void) {
  struct ism43xxx_ctx *c = (struct ism43xxx_ctx *) calloc(1, sizeof(*c));
  const struct mgos_config_wifi_ism43xxx *cfg =
      mgos_sys_config_get_wifi_ism43xxx();
  if (cfg->spi == NULL) {
    c->spi = mgos_spi_get_global();
    if (c->spi == NULL) {
      LOG(LL_ERROR, ("SPI is not configured, make sure spi.enable is true"));
      return;
    }
  } else {
    struct mgos_config_spi spi_cfg = {
        .enable = true, .cs0_gpio = -1, .cs1_gpio = -1, .cs2_gpio = -1};
    if (!mgos_spi_config_from_json(mg_mk_str(cfg->spi), &spi_cfg) ||
        (c->spi = mgos_spi_create(&spi_cfg)) == NULL) {
      LOG(LL_ERROR, ("Invalid SPI cfg"));
      return;
    }
  }
  c->spi_freq = cfg->spi_freq;
  c->cs_gpio = cfg->cs_gpio;
  c->rst_gpio = cfg->rst_gpio;
  c->drdy_gpio = cfg->drdy_gpio;
  c->boot0_gpio = cfg->boot0_gpio;
  c->wakeup_gpio = cfg->wakeup_gpio;
  c->poll_timer_id = MGOS_INVALID_TIMER_ID;
  c->startup_timer_id = MGOS_INVALID_TIMER_ID;

  if (ism43xxx_init(c)) {
    s_ctx = c;
  }
}

void mgos_wifi_dev_deinit(void) {
  ism43xxx_reset(s_ctx, true /* hold */);
}

bool mgos_wifi_ism43xxx_init(void) {
  /* Real init happens in mgos_wifi_dev_init */
  return true;
}
