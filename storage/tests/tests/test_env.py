# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

target = "all"
import os

from system_tools.config import (HostTargetConfig, IPUStorageConfig,
                                 StorageTargetConfig, import_base_test)
from system_tools.docker import (CMDSenderContainer, HostTargetContainer,
                                 IPUStorageContainer, StorageTargetContainer)
from system_tools.terminals import SSHTerminal

BaseTest = import_base_test(target)


class TestTerminalConnect(BaseTest):
    def setUp(self):
        self.storage_target_terminal = SSHTerminal(StorageTargetConfig())
        self.ipu_storage_terminal = SSHTerminal(IPUStorageConfig())
        self.host_target_terminal = SSHTerminal(HostTargetConfig())

    def runTest(self):
        self.assertEqual(
            self.storage_target_terminal.execute("whoami"),
            self.storage_target_terminal.config.username,
        )
        self.assertEqual(
            self.ipu_storage_terminal.execute("whoami"),
            self.ipu_storage_terminal.config.username,
        )
        self.assertEqual(
            self.host_target_terminal.execute("whoami"),
            self.host_target_terminal.config.username,
        )

    def tearDown(self):
        pass


class TestTerminalConnectHasRootPrivileges(BaseTest):
    def setUp(self):
        self.storage_target_terminal = SSHTerminal(StorageTargetConfig())
        self.ipu_storage_terminal = SSHTerminal(IPUStorageConfig())
        self.host_target_terminal = SSHTerminal(HostTargetConfig())

    def runTest(self):
        self.assertEqual(
            self.storage_target_terminal.execute("sudo whoami"),
            "root",
        )
        self.assertEqual(
            self.ipu_storage_terminal.execute("sudo whoami"),
            "root",
        )
        self.assertEqual(
            self.host_target_terminal.execute("sudo whoami"),
            "root",
        )

    def tearDown(self):
        pass


class TestDeployContainers(BaseTest):
    def setUp(self):
        self.storage_target_terminal = SSHTerminal(StorageTargetConfig())
        self.ipu_storage_terminal = SSHTerminal(IPUStorageConfig())
        self.host_target_terminal = SSHTerminal(HostTargetConfig())

        self.branch = "main"
        self.repository_url = "'https://github.com/ipdk-io/ipdk.git'"
        self.shared_dir = os.path.join(HostTargetConfig().vm_share_dir_path, "shared")

    def runTest(self):
        terminals = (
            self.storage_target_terminal,
            self.ipu_storage_terminal,
            self.host_target_terminal,
        )
        for terminal in terminals:
            cmd = f"sudo rm -rf {self.storage_target_terminal.config.workdir}"
            terminal.execute(cmd)
            cmd = f"mkdir -p {self.storage_target_terminal.config.workdir}"
            terminal.execute(cmd)
            cmd = f"cd {self.storage_target_terminal.config.workdir} && git clone --branch {self.branch} {self.repository_url}"
            terminal.execute(cmd)
            cmd = f"ls {self.storage_target_terminal.config.workdir}/ipdk/build"
            terminal.execute(cmd)
            cmd = f"cd {self.storage_target_terminal.config.storage_dir} && git log"
            terminal.execute(cmd)

        self.storage_target_container = StorageTargetContainer()
        self.assertIn(
            "storage-target", self.storage_target_terminal.execute("docker ps")
        )

        self.ipu_storage_terminal.client.exec_command(f"mkdir -p {self.shared_dir}")
        self.ipu_storage_container = IPUStorageContainer()
        self.assertIn(
            "ipu-storage-container", self.ipu_storage_terminal.execute("docker ps")
        )

        self.host_target_container = HostTargetContainer()
        # container runs by the command below and stopped immediately after cmd execution
        self.assertIn("host-target", self.host_target_terminal.execute("docker ps -a"))

        self.cmd_sender_container = CMDSenderContainer(IPUStorageConfig())
        self.assertIn("cmd-sender", self.ipu_storage_terminal.execute("docker ps"))

    def tearDown(self):
        self.storage_target_container.stop()
        self.host_target_container.stop()
        self.ipu_storage_container.stop()
        self.cmd_sender_container.stop()
