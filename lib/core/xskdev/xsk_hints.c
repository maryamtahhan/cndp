/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2022 Red Hat, Inc.
 */

#include "xsk_hints.h"

/** Double linked list of xdp hints structures. */
TAILQ_HEAD(xsk_xdp_hints_list, xsk_xdp_hints) xdp_hints_structs_list;

struct xsk_xdp_hints *
find_xdp_hints_struct_by_name(const char *name)
{
    struct xsk_xdp_hints *hint = NULL;

    TAILQ_FOREACH (hint, &xdp_hints_structs_list, next) {
        if (!strcmp(name, hint->symbol_name))
            break;
    }

    return hint;
}

struct xsk_xdp_hints *
find_xdp_hints_struct_by_id(const uint64_t btf_id)
{
    struct xsk_xdp_hints *hint = NULL;

    /* Search for the xdp hints struct*/
    TAILQ_FOREACH (hint, &xdp_hints_structs_list, next) {
        if (btf_id == hint->btf_id)
            break;
    }

    return hint;
}

/* register xdp_hints struct */
void
xdp_hints_register(struct xsk_xdp_hints *hints)
{
    int err                 = 0;
    const char *module_name = hints->module;
    struct btf *vmlinux_btf, *module_btf = NULL;
    int32_t type_id;

    vmlinux_btf = btf__load_vmlinux_btf();
    err         = libbpf_get_error(vmlinux_btf);
    if (err) {
        CNE_ERR("ERROR(%d): btf__load_vmlinux_btf()\n", err);
        goto out;
    }

    module_btf = btf__load_module_btf(module_name, vmlinux_btf);
    err        = libbpf_get_error(module_btf);
    if (err) {
        CNE_ERR("ERROR(%d): btf__load_module_btf() module_name: %s\n", err, module_name);
        goto out;
    }

    type_id = btf__find_by_name(module_btf, hints->symbol_name);
    if (type_id < 0) {
        err = type_id;
        CNE_ERR("ERROR(%d): btf__find_by_name() symbol_name: %s\n", err, hints->symbol_name);
        goto out;
    }

    hints->btf_id = type_id;

    CNE_DEBUG("REGISTERING XDP_HINT %s, with BTF_ID %lu\n", hints->symbol_name, hints->btf_id);
    TAILQ_INSERT_TAIL(&xdp_hints_structs_list, hints, next);

out:
    btf__free(module_btf);
    btf__free(vmlinux_btf);
}

static __cne_always_inline void
process_xdp_hints_ixgbe(void *buf)
{
    pktmbuf_t *p            = (pktmbuf_t *)buf;
    struct xdp_hints *hints = NULL;

    hints = pktmbuf_mtod_offset(p, struct xdp_hints *, -(sizeof(struct xdp_hints)));

    p->hash        = hints->common.rx_hash32;
    p->packet_type = hints->rss_type;
}

struct xsk_xdp_hints xdp_hints_ixgbe = {
    .module = "ixgbe", .symbol_name = "xdp_hints_ixgbe", .process_hints = process_xdp_hints_ixgbe};

XDP_HINTS_REGISTER(xdp_hints_ixgbe);

CNE_INIT_PRIO(xskhints_constructor, START) { TAILQ_INIT(&xdp_hints_structs_list); }
