# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('xskdev.c', 'xsk_hints.c')
headers = files('xskdev.h', 'xsk_hints.h')

deps += [cne, uds, mmap, mempool, pktmbuf, bpf_dep]

libxskdev = library(libname, sources, install: true, dependencies: deps)
xskdev = declare_dependency(link_with: libxskdev, include_directories: include_directories('.'))

cndp_libs += xskdev
