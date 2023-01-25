# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Red Hat, Inc.

if cne_verbose
	message('Build xskmap_read')
endif

deps += [bpf_dep, uds]

sources = files('xskmap_read.c')

xskmap_load_send = executable('xskmap_read', sources, dependencies: deps, install: true)
