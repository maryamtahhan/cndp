/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <net/cne_ether.h>           // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                    // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>                // for proto_in_ifunc
#include <cnet_drv.h>                // for drv_entry
#include <cnet_route.h>              // for
#include <cnet_arp.h>                // for arp_entry
#include <netinet/in.h>              // for ntohs
#include <netpacket/packet.h>        // for sockaddr_ll
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
// #include <linux/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stddef.h>        // for NULL
#include <sys/types.h>
#include <fcntl.h>
#include <bsd/string.h>
#include <sys/uio.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <xskdev.h>
#include <pktmbuf.h>        // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>        // for
#include <cnet_eth.h>
#include <hexdump.h>
#include <cnet_netif.h>        // for
#include <netinet/if_ether.h>
#include <pmd_tap.h>
#include <cnet_node_names.h>
#include "punt_ether_kernel_priv.h"

#define PREFETCH_CNT 6

static void
_hexdump(FILE *f, const char *title, const void *buf, unsigned int len)
{
    unsigned int i, out, ofs;
    const unsigned char *data = buf;
    char line[128]; /* Space needed 8+16*3+3+16 == 75 */

    if (f == NULL)
        f = stdout;

    CNE_WARN("%s at [%p], len=%u\n", title ? "" : "  Dump data", data, len);
    ofs = 0;
    while (ofs < len) {
        /* Format the line in the buffer */
        out = snprintf(line, 128, "%08X:", ofs);
        for (i = 0; i < 16; i++) {
            if (ofs + i < len)
                snprintf(line + out, 128 - out, " %02X", (data[ofs + i] & 0xff));
            else
                strcpy(line + out, "   ");
            out += 3;
        }

        for (; i <= 16; i++)
            out += snprintf(line + out, 128 - out, " | ");

        for (i = 0; ofs < len && i < 16; i++, ofs++) {
            unsigned char c = data[ofs];

            if (c < ' ' || c > '~')
                c = '.';
            out += snprintf(line + out, 128 - out, "%c", c);
        }
        CNE_WARN("%s\n", line);
    }

    fflush(f);
}

static __cne_always_inline void
punt_ether_kernel_process_mbuf(struct cne_node *node, pktmbuf_t **mbufs, uint16_t cnt)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;

    CNE_WARN("%s\n", __FUNCTION__);

    if (ctx->sock >= 0) {
#if TAP_PMD
        // NEED TO RESET THE MBUF data ptr and length...
        for (int i = 0; i < cnt; i++) {
            pktmbuf_adj_offset(mbufs[i], -(mbufs[i]->l2_len));

            if (mbufs[i]->ol_flags && CNE_MBUF_TYPE_BCAST)
                CNE_WARN("IT's a broadcast frame %s\n", __FUNCTION__);

            if ((mbufs[i]->packet_type & CNE_PTYPE_L2_MASK) == CNE_PTYPE_L2_ETHER_ARP)
                CNE_WARN("IT's an ARP frame %s\n", __FUNCTION__);

            _hexdump(NULL, "ETHER FRAME", pktmbuf_mtod(mbufs[i], void *),
                     pktmbuf_data_len(mbufs[i]));
        }

        int nb = pktdev_tx_burst(ctx->lport, mbufs, cnt);
        if (nb == PKTDEV_ADMIN_STATE_DOWN)
            CNE_WARN("Failed to send packets: %s\n", strerror(errno));
#else
        struct cne_ether_hdr *eth_hdr;
        struct sockaddr_ll sll = {0};
        size_t len;
        unsigned char *buf;
        uint32_t sip, tip;

        for (int i = 0; i < cnt; i++) {
            eth_hdr = pktmbuf_mtod_offset(mbufs[i], struct cne_ether_hdr *, -(mbufs[i]->l2_len));
            len     = pktmbuf_data_len(mbufs[i]) + +(mbufs[i]->l2_len);
            buf     = (char *)eth_hdr;

            if (mbufs[i]->ol_flags && CNE_MBUF_TYPE_BCAST)
                CNE_WARN("IT's a broadcast frame %s\n", __FUNCTION__);

            if ((mbufs[i]->packet_type & CNE_PTYPE_L2_MASK) == CNE_PTYPE_L2_ETHER_ARP)
                CNE_WARN("IT's an ARP frame %s\n", __FUNCTION__);

            _hexdump(NULL, "ETHER FRAME", eth_hdr, len);

            sll.sll_family   = AF_PACKET;
            sll.sll_protocol = htons(ETH_P_ALL);        // htons(eth_hdr->ether_type);
            sll.sll_ifindex  = ctx->if_index;
            sll.sll_halen    = ETHER_ADDR_LEN;
            sll.sll_hatype   = htons(eth_hdr->ether_type);
            sll.sll_addr[6]  = 0x00;
            sll.sll_addr[7]  = 0x00;
            memcpy(sll.sll_addr, eth_hdr->d_addr.ether_addr_octet, ETHER_ADDR_LEN);

            struct ether_arp *req = (struct ether_arp *)(buf + mbufs[i]->l2_len);

            // req->arp_hrd=htons(ARPHRD_ETHER);
            // req->arp_pro=htons(ETH_P_IP);
            // req->arp_op=htons(ARPOP_REQUEST);

            // memcpy(&tip, &req->arp_tpa,  sizeof(tip));
            // memcpy(&sip, &req->arp_spa,  sizeof(sip));
            // sip=ntohl(sip);
            // tip=ntohl(tip);
            // memcpy(&req->arp_tpa, &tip, sizeof(req->arp_tpa));
            // memcpy(&req->arp_spa, &sip, sizeof(req->arp_spa));

            // CNE_WARN("%s req->arp_hrd=%x \n", __FUNCTION__, req->arp_hrd);
            // CNE_WARN("%s req->arp_pro=%x\n", __FUNCTION__,req->arp_pro);
            // CNE_WARN("%s req->arp_hln=%d \n", __FUNCTION__,req->arp_hln);
            // CNE_WARN("%s req->arp_pln=%d \n", __FUNCTION__,req->arp_pln);
            // CNE_WARN("%s req->arp_op=%x \n", __FUNCTION__,req->arp_op);

            if (sendto(ctx->sock, &req, sizeof(req), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
                CNE_WARN("Failed to send packets: %s\n", strerror(errno));

            // if (sendto(ctx->sock, &buf, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
            //     CNE_WARN("Failed to send packets: %s\n", strerror(errno));
        }

        if (cnt)
            pktmbuf_free_bulk(mbufs, cnt);
#endif
    }
}

static uint16_t
punt_ether_kernel_node_process(struct cne_graph *graph __cne_unused, struct cne_node *node,
                               void **objs, uint16_t nb_objs)
{
    uint16_t n_left_from;
    pktmbuf_t *mbufs[PREFETCH_CNT], **pkts;
    int k;

    CNE_WARN("%s\n", __FUNCTION__);

    pkts        = (pktmbuf_t **)objs;
    n_left_from = nb_objs;

    for (k = 0; k < PREFETCH_CNT && k < n_left_from; k++)
        cne_prefetch0(pktmbuf_mtod_offset(pkts[k], void *, sizeof(struct cne_ether_hdr)));

    while (n_left_from >= PREFETCH_CNT) {
        /* Prefetch next-next mbufs */
        if (likely(n_left_from > ((PREFETCH_CNT * 3) - 1))) {
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 0]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 1]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 2]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 3]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 4]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 5]);
        }

        /* Prefetch next mbuf data */
        if (likely(n_left_from > ((PREFETCH_CNT * 2) - 1))) {
            uint16_t pre = PREFETCH_CNT;

            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 0], void *, pkts[pre + 0]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 1], void *, pkts[pre + 1]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 2], void *, pkts[pre + 2]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 3], void *, pkts[pre + 3]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 4], void *, pkts[pre + 4]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 5], void *, pkts[pre + 5]->l2_len));
        }

        memcpy(mbufs, pkts, (PREFETCH_CNT * sizeof(void *)));

        pkts += PREFETCH_CNT;
        n_left_from -= PREFETCH_CNT;

        punt_ether_kernel_process_mbuf(node, mbufs, PREFETCH_CNT);
    }

    while (n_left_from > 0) {
        mbufs[0] = pkts[0];

        n_left_from--;
        pkts++;

        punt_ether_kernel_process_mbuf(node, mbufs, 1);
    }

    return nb_objs;
}

#define TAP_NAME "punt_ether"
static int
punt_ether_kernel_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;

#if TAP_PMD
    lport_cfg_t cfg = {0}; /**< CFG for tun/tap setup */
    ctx->mmap       = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (ctx->mmap == NULL)
        cne_panic("Failed to mmap(%lu, %s) memory",
                  (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                  mmap_name_by_type(MMAP_HUGEPAGE_4KB));

    memset(&cfg, 0, sizeof(cfg));

    strlcpy(cfg.name, TAP_NAME, sizeof(cfg.name));
    strlcpy(cfg.pmd_name, PMD_NET_TAP_NAME, sizeof(cfg.pmd_name));
    strlcpy(cfg.ifname, TAP_NAME, sizeof(cfg.ifname));

    cfg.addr = cfg.umem_addr = mmap_addr(ctx->mmap);
    cfg.umem_size            = mmap_size(ctx->mmap, NULL, NULL);
    cfg.qid                  = LPORT_DFLT_START_QUEUE_IDX;
    cfg.bufsz                = LPORT_FRAME_SIZE;
    cfg.bufcnt               = DEFAULT_MBUF_COUNT;
    cfg.rx_nb_desc           = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.tx_nb_desc           = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.pi =
        pktmbuf_pool_create(mmap_addr(ctx->mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);

    ctx->lport = pktdev_port_setup(&cfg);
    if (ctx->lport < 0)
        CNE_ERR_RET("Failed to create TAP device\n");

    if (netdev_set_link_up(TAP_NAME) < 0)
        CNE_ERR_RET("netdev_set_link_up(%d) failed\n", ctx->lport);
#else
    ctx->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sock < 0)
        CNE_ERR_RET("Failed to open RAW socket\n");

    ctx->ti = tun_alloc(IFF_TAP, TAP_NAME);
    if (ctx->ti == NULL)
        CNE_ERR_RET("Failed to create %s\n", TAP_NAME);
    ctx->if_index = if_nametoindex(TAP_NAME);
#endif

    return 0;
}

static void
punt_ether_kernel_node_fini(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;
#if TAP_PMD
    if (pktdev_close(ctx->lport) < 0)
        CNE_WARN("pktdev_close(%d) failed\n", ctx->lport);
    mmap_free(ctx->mmap);

#else
    if (tun_free(ctx->ti) < 0)
        CNE_ERR("[cyan]Failed to free tun/tap interface[]\n");
#endif
    if (ctx->sock >= 0) {
        close(ctx->sock);
        ctx->sock = -1;
    }
}

static struct cne_node_register punt_ether_kernel_node_base = {
    .process = punt_ether_kernel_node_process,
    .name    = PUNT_ETHER_NODE_NAME,

    .init = punt_ether_kernel_node_init,
    .fini = punt_ether_kernel_node_fini,

};

struct cne_node_register *
punt_ether_kernel_node_get(void)
{
    return &punt_ether_kernel_node_base;
}

CNE_NODE_REGISTER(punt_ether_kernel_node_base);
