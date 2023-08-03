# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

STORAGE_DIR_PATH = "ipdk/build/storage"
DEFAULT_NQN = "nqn.2016-06.io.spdk:cnode0"

LP_INTERNAL_IP = "200.1.1.1/24"
ACC_INTERNAL_IP = "200.1.1.3/24"

DEFAULT_SPDK_PORT = 5260
DEFAULT_NVME_PORT = 4420
DEFAULT_SMA_PORT = 8080
DEFAULT_QMP_PORT = 5555
DEFAULT_HOST_TARGET_SERVICE_PORT_IN_VM = 50051
DEFAULT_MAX_RAMDRIVE = 64
DEFAULT_MIN_RAMDRIVE = 1
FIO_COMMON = {
    "runtime": 1,
    "numjobs": 1,
    "time_based": 1,
    "group_reporting": 1,
}
FIO_IO_PATTERNS = [
    "RANDRW",
    "RANDREAD",
    "WRITE",
    "READWRITE",
    "RANDWRITE",
    "READ",
    "TRIM",
]
DEFAULT_TARGETS = [
    "kvm",
]
