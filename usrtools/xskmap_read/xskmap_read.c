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
#include <cne.h>
#include <uds.h>
#include <cne_stdio.h>
#include <cne_log.h>

int
main(int argc __cne_unused, char **argv __cne_unused)
{
    int fd;
    const char *file = "/tmp/map/xsk_map";

    fd = bpf_obj_get(file);
    if (fd < 0)
        printf("Couldn't get fd %s\n", strerror(errno));
    else
        printf("bpf: get fd:%d\n", fd);

    return 0;
}