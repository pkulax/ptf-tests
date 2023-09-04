# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

target = "ipu_performance"
import time

from system_tools.config import TestConfig, import_base_test
from system_tools.const import FIO_NUM_RUN, FIO_PERCENT_PASS, FIO_TARGET_PERFORMANCE
from system_tools.errors import CommandException
from system_tools.log import logging
from system_tools.parsers import fio_performance_parser
from system_tools.terminals import SSHTerminal
from system_tools.test_platform import PlatformFactory


BaseTest = import_base_test(target)


class TestIPUPerformance(BaseTest):
    def setUp(self):
        self.tests_config = TestConfig()
        self.platforms_factory = PlatformFactory()
        self.lp_platform = self.platforms_factory.get_lp_platform()
        self.lp_platform.set()
        self.host_platform = self.platforms_factory.get_host_platform()
        self.host_platform.set()

    def runTest(self):
        pass_fio = 0
        for i in range(FIO_NUM_RUN):
            result = self.host_platform.run_performance_fio()
            iops = fio_performance_parser(result)
            pass_fio = pass_fio + 1 if iops > FIO_TARGET_PERFORMANCE else pass_fio
        assert pass_fio >= FIO_PERCENT_PASS/100 * FIO_NUM_RUN

    def tearDown(self):
        self.lp_platform.clean()
        self.host_platform.clean()
