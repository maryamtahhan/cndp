/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Red Hat, Inc.
 * Copyright (c) 2022-2023 Intel Corporation.
 */

#include "xskmap_load_send.h"

/* Long options start at 256 to distinguish from short options */
#define OPT_NO_COLOR     "no-color"
#define OPT_NO_COLOR_NUM 256
#define HOST_NAME_LEN    32

static int parse_args(int argc, char **argv);

static void
print_usage(char *prog_name)
{
    cne_printf("Usage: %s [-h] \n"
               "  -L [level]     Enable a logging level\n"
               "  -m <path>      The pinned xsk_map\n"
               "  --%-12s Disable color output\n",
               prog_name, OPT_NO_COLOR);
}

static int
parse_args(int argc, char **argv)
{
    // clang-format off
    struct option lgopts[] = {
        {OPT_NO_COLOR, no_argument, NULL, OPT_NO_COLOR_NUM},
        {NULL, 0, 0, 0}
    };
    // clang-format on
    int opt, option_index;
    char log_level[16] = {0};

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hL:m:u:n:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;
        case 'L':
            strlcpy(log_level, optarg, sizeof(log_level));
            if (cne_log_set_level_str(log_level)) {
                CNE_ERR("Invalid command option\n");
                print_usage(argv[0]);
                return -1;
            }
            break;
        case 'm':
            strlcpy(info.map_path, optarg, sizeof(info.map_path));
            break;
        case OPT_NO_COLOR_NUM:
            tty_disable_color();
            break;

        default:
            CNE_ERR("Invalid command option\n");
            print_usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

static int
send_map_fd(int sock, int fd)
{
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg                     = {0};
    struct iovec iov;
    char value[UDS_MAX_CMD_LEN] = {0};

    snprintf(value, sizeof(value), "%s,%d", UDS_FD_ACK_MSG, fd);

    iov.iov_base = &value;
    iov.iov_len  = strnlen(value, sizeof(value));

    msg.msg_name       = NULL;
    msg.msg_namelen    = 0;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_flags      = 0;
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    *(int *)CMSG_DATA(cmsg) = fd;
    int ret                 = sendmsg(sock, &msg, 0);

    if (ret < 0)
        CNE_ERR_RET_VAL(-errno, "Failed to send xsk_map fd with error=%s\n", strerror(errno));

    return ret;
}

static int
connect_host(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    if (send(c->s, UDS_HOST_OK_MSG, sizeof(UDS_HOST_OK_MSG), 0) <= 0)
        CNE_ERR_RET("Failed to send %s message %s\n", UDS_HOST_OK_MSG, strerror(errno));
    else
        CNE_DEBUG("Sent %s msg\n", UDS_HOST_OK_MSG);

    return 0;
}

static int
fin_ack(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    if (send(c->s, UDS_FIN_ACK_MSG, sizeof(UDS_FIN_ACK_MSG), 0) <= 0)
        CNE_ERR_RET("Failed to send %s message %s\n", UDS_FIN_ACK_MSG, strerror(errno));
    else
        CNE_DEBUG("Sent %s msg\n", UDS_FIN_ACK_MSG);

    return 0;
}

static int
send_xskmap_fd(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    if (!c->s || !c->info->xsk_map_fd)
        return -1;
    return send_map_fd(c->s, c->info->xsk_map_fd);
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    struct map_info *fwd = arg;

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        /* Terminate the application if not USR1 signal, allows for GDB breakpoint setting */
        if (val == SIGUSR1) {
            vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
            return;
        }

        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);

        fwd->timer_quit = 1;
        break;

    case CNE_CALLED_EXIT:
        if (val)
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);

        if (fwd) {
            cne_printf(">>> [magenta]Closing[]\n");
            uds_destroy(NULL);
            fwd->timer_quit = 1;
        }
        break;

    case CNE_USER_EXIT:
        break;

    default:
        break;
    }
    fflush(stdout);
}

static int
do_attach(int idx, int prog_fd, const char *name)
{
    int err;
    int xdp_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

    err = bpf_xdp_attach(idx, prog_fd, xdp_flags, NULL);
    if (err < 0) {
        printf("ERROR: failed to attach program to %s\n", name);
        return err;
    }

    return err;
}

int
main(int argc, char **argv)
{
    int signals[] = {SIGINT, SIGUSR1, SIGTERM};
    int ret       = 0, err;
    const uds_group_t *grp;
    int fd;
    char filename[]          = "xdp_prog_kern.o";
    const char *prog_name    = "xdp_filter";
    struct bpf_program *prog = NULL;
    struct bpf_program *pos;
    const char *sec_name;
    int prog_fd = -1, map_fd = -1;
    struct bpf_object *obj;

    if (cne_init() || parse_args(argc, argv))
        return -1;

    cne_on_exit(__on_exit, (void *)&info, signals, cne_countof(signals));

    // snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    if (access(filename, O_RDONLY) < 0) {
        printf("error accessing file %s: %s\n", filename, strerror(errno));
        return 1;
    }

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
        return 1;

    prog = bpf_object__next_program(obj, NULL);
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    err = bpf_object__load(obj);
    if (err) {
        printf("Does kernel support devmap lookup?\n");
        /* If not, the error message will be:
         *  "cannot pass map_type 14 into func bpf_map_lookup_elem#1"
         */
        return 1;
    }

    bpf_object__for_each_program(pos, obj)
    {
        sec_name = bpf_program__section_name(pos);
        if (sec_name && !strcmp(sec_name, prog_name)) {
            prog = pos;
            break;
        }
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        printf("program not found: %s\n", strerror(prog_fd));
        return 1;
    }
    printf("bpf: prog_fd:%d\n", prog_fd);
    fd = map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "xsks_map"));
    if (map_fd < 0) {
        printf("map not found: %s\n", strerror(map_fd));
        return 1;
    }
    printf("bpf: map_fd:%d\n", map_fd);

    err = bpf_obj_pin(map_fd, "/tmp/map/xsk_map");
    if (err) {
        printf("FAILED TO PIN THE XSK MAP error %s\n", strerror(errno));
        return 1;
    }

    err = do_attach(if_nametoindex("eno1"), prog_fd, "eno1");
    if (err)
        return 1;

#if 0
    fd = bpf_obj_get(info.map_path);
    if (fd < 0)
        CNE_ERR_RET("Failed to open pinned xsk_map:%s err:%s\n", info.map_path, strerror(errno));
#endif
    CNE_DEBUG("xsk_map fd =%d\n", fd);

    info.uds_info = uds_get_default(&info);
    if (!info.uds_info)
        CNE_ERR_RET("UDS failed to initialize: %s\n", strerror(errno));

    info.uds_info->xsk_map_fd = fd;

    grp = uds_get_group_by_name(info.uds_info, NULL);
    if (grp == NULL)
        CNE_ERR_RET("Get default group failed\n");

    CNE_DEBUG("info->uds_info->sock %d\n", info.uds_info->sock);

    if (uds_register(grp, UDS_CONNECT_MSG, connect_host) < 0)
        CNE_ERR_RET("Failed to register the %s command\n", UDS_CONNECT_MSG);

    if (uds_register(grp, UDS_XSK_MAP_FD_MSG, send_xskmap_fd) < 0)
        CNE_ERR_RET("Failed to register the %s command\n", UDS_XSK_MAP_FD_MSG);

    if (uds_register(grp, UDS_FIN_MSG, fin_ack) < 0)
        CNE_ERR_RET("Failed to register the %s command\n", UDS_FD_ACK_MSG);

    CNE_DEBUG("REGISTERED ALL COMMANDS\n");

    cne_printf(">>> [magenta]Waiting to send xsk_map fd upon request. To quit type ^c\n");
    for (;;) {
        sleep(1);
        if (info.timer_quit)
            break;
    }

    return ret;
}
