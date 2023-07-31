/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */
#ifndef __INCLUDE_punt_ether_kernel_PRIV_H__
#define __INCLUDE_punt_ether_kernel_PRIV_H__

#include <cne_common.h>
#include <tun_alloc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TAP_PMD 1

struct punt_ether_kernel_node_elem;
struct punt_ether_kernel_node_ctx;
typedef struct punt_ether_kernel_node_elem punt_ether_kernel_node_elem_t;

/**
 * @internal
 *
 * PUNT Kernel node context structure.
 */
typedef struct punt_ether_kernel_node_ctx {
    int sock;
#ifndef TAP_PMD
    struct tap_info *ti;
    int if_index;
#else
    int lport;
    mmap_t *mmap;
#endif
} punt_ether_kernel_node_ctx_t;

/**
 * @internal
 *
 * PUNT Kernel node list element structure.
 */
struct punt_ether_kernel_node_elem {
    struct punt_ether_kernel_node_elem *next; /**< Pointer to the next node element. */
    struct punt_ether_kernel_node_ctx *ctx;   /**< node context. */
    cne_node_t nid;                           /**< Node identifier of the PUNT ether Kernel node. */
};

/**
 * @internal
 *
 * PUNT Kernel node main structure.
 */
struct punt_ether_kernel_node_main {
    punt_ether_kernel_node_elem_t *head; /**< Pointer to the head node element. */
};

/**
 * @internal
 *
 * Get the PUNT Kernel node.
 *
 * @return
 *   Pointer to the PUNT Kernel node.
 */
CNDP_API struct cne_node_register *punt_ether_kernel_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_punt_ether_kernel_PRIV_H__ */
