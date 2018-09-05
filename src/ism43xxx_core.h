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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "common/mg_str.h"

#include "mgos_net.h"
#include "mgos_spi.h"
#include "mgos_timers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per datasheet, 4 is the maximum number of clients supported. */
#define ISM43XXX_AP_MAX_CLIENTS 4

enum ism43xxx_phase {
  ISM43XXX_PHASE_RESET = 0,
  ISM43XXX_PHASE_INIT = 1,
  ISM43XXX_PHASE_CMD = 2,
  ISM43XXX_PHASE_RESP = 3,
  ISM43XXX_PHASE_DATA = 4,
};

enum ism43xxx_mode {
  ISM43XXX_MODE_IDLE = 0,
  ISM43XXX_MODE_STA = 1,
  ISM43XXX_MODE_AP = 2,
};

struct ism43xxx_cmd;

struct ism43xxx_client_info {
  uint8_t mac[6];
  int rssi;
  int gen;
};

/* NB: when adding to this struct, add code to ism43xxx_reset to
 * (re-)initialize the new member properly. */
struct ism43xxx_ctx {
  /* Physical interface configuration */
  int spi_freq;
  struct mgos_spi *spi;
  int cs_gpio, rst_gpio, drdy_gpio, boot0_gpio, wakeup_gpio;
  /* Current mode: IDLE, STA or AP. */
  enum ism43xxx_mode mode;
  /* Current SPI communication phase: reset, init, command or data. */
  enum ism43xxx_phase phase;
  /* Command sequences, current and queued. */
  const struct ism43xxx_cmd *cur_seq, *seq_q[3];
  const struct ism43xxx_cmd *cur_cmd;

  mgos_timer_id startup_timer_id;
  mgos_timer_id poll_timer_id;
  uint8_t mac[6];
  /* Station-related stuff, valid when mode == STA. */
  int8_t sta_rssi;
  char *sta_dns;
  struct mgos_net_ip_info sta_ip_info;
  /* AP-related stuff, valid when mode == AP. */
  struct mgos_net_ip_info ap_ip_info;
  struct ism43xxx_client_info ap_clients[ISM43XXX_AP_MAX_CLIENTS];
  /* Flags */
  unsigned int cur_cmd_timeout : 8;
  unsigned int idle_timeout : 8;
  unsigned int need_poll : 1;
  unsigned int print_mac : 1;
  unsigned int print_info : 1;
  unsigned int sta_connected : 1;
};

struct ism43xxx_cmd {
  /* Command */
  const char *cmd;
  /* Timeout, in seconds. 0 means default. */
  int timeout;
  /* Payload handler (optional). */
  bool (*ph)(struct ism43xxx_ctx *c, bool ok, struct mg_str payload);
  /* cmd is dynamically allocated and should be freed when done. */
  bool free_cmd;
};

bool ism43xxx_init(struct ism43xxx_ctx *c);

void ism43xxx_reset(struct ism43xxx_ctx *c, bool hold);

bool ism43xxx_send_cmd_seq(struct ism43xxx_ctx *c,
                           const struct ism43xxx_cmd *seq, bool copy);

bool ism43xxx_ignore_error(struct ism43xxx_ctx *c, bool ok, struct mg_str p);

bool ism43xxx_parse_mac(const char *s, uint8_t mac[6]);

void ism43xxx_set_sta_status(struct ism43xxx_ctx *c, bool connected,
                             bool force);

bool ism43xxx_mr_cb(struct ism43xxx_ctx *c, bool ok, struct mg_str p);

#ifdef __cplusplus
}
#endif
