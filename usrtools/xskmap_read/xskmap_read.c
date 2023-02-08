#include <stdio.h>
#include <getopt.h>
#include <bsd/string.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_link.h>
#if USE_LIBXDP
#include <xdp/xsk.h>
#else
#include <bpf/xsk.h>
#endif
#include "xskmap_read.h"

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
        opt = getopt_long(argc, argv, "hL:m:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;
        case 'm':
            memset(info.map_path, 0, sizeof(info.map_path));
            strlcpy(info.map_path, optarg, sizeof(info.map_path));
            break;
        case 'L':
            strlcpy(log_level, optarg, sizeof(log_level));
            if (cne_log_set_level_str(log_level)) {
                CNE_ERR("Invalid command option\n");
                print_usage(argv[0]);
                return -1;
            }
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

int
main(int argc __cne_unused, char **argv __cne_unused)
{
    int fd;
    const char *file = "/tmp/map/xsk_map";

    strlcpy(info.map_path, file, sizeof(info.map_path));
    if (parse_args(argc, argv))
        return -1;

    fd = bpf_obj_get(info.map_path);
    if (fd < 0)
        printf("Couldn't get fd %s\n", strerror(errno));
    else
        printf("bpf: get fd:%d\n", fd);

    return 0;
}