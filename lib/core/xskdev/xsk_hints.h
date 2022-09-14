/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2022 Red Hat, Inc.
 */

#ifndef _XSK_HINTS_H_
#define _XSK_HINTS_H_

#include <sys/queue.h>        // for TAILQ_FOREACH, TAILQ_HEAD_INITIALIZER
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <getopt.h>
#include <time.h>
#include <bpf/btf.h>
#include <cne_log.h>
#include <pktmbuf.h>

#if USE_LIBXDP
#include <xdp/libxdp.h>
#endif

/**
 * @file
 *
 * CNE XSK Hints low-level abstraction
 *
 * This file provides a low-level abstraction for applications to XSK hints APIs.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*process_hints_t)(void *buf);

/**
 * A xdp hints abstraction.
 */
struct xsk_xdp_hints {
    TAILQ_ENTRY(xsk_xdp_hints) next; /**< Next in list */
    const char *module;              /**< Module name */
    const char *symbol_name;         /**< Symbol name */
    uint64_t btf_id;                 /**< BTF ID looked up at reg time */
    process_hints_t process_hints;   /**< Callback function to process this type of hint */
};

/**
 * Register an xdp hints structure.
 *
 * @param hints
 *   A pointer to a xsk_xdp_hints structure describing the hints
 *   to be registered.
 */
void xdp_hints_register(struct xsk_xdp_hints *hints);

#define XDP_HINTS_REGISTER(hints) \
    CNE_INIT(hintinit_##hints) { xdp_hints_register(&hints); }

struct xsk_xdp_hints *find_xdp_hints_struct_by_name(const char *name);
struct xsk_xdp_hints *find_xdp_hints_struct_by_id(const uint64_t btf_id);

/*****************************************************
 *                                                   *
 *        TEMPORARY STRUCT DECLARATIONS              *
 *                                                   *
 *****************************************************/
struct xdp_hints {
    uint16_t rss_type;
    struct xdp_hints_common common;
};

struct xdp_hints_ixgbe_timestamp {
    uint64_t rx_timestamp;
    struct xdp_hints base;
};

#ifdef __cplusplus
}
#endif

#endif /* _XSK_HINTS_H_ */