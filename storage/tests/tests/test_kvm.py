# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

target = "kvm"
from system_tools.config import TestConfig, import_base_test
from system_tools.log import logging
from system_tools.test_platform import PlatformFactory

BaseTest = import_base_test(target)


class TestKvm(BaseTest):
    def setUp(self):
        self.tests_config = TestConfig()
        self.platforms_factory = PlatformFactory()
        self.platform = self.platforms_factory.get_lp_platform()
        self.platform.set()

    def runTest(self):
        pass

    def tearDown(self):
        pass
        #self.platform.clean()
