# Copyright (c) 2022 Intel Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
DPDK L2 Exact Match (match fields, actions) with TAP Port
"""

# in-built module imports
import time
import sys

# Unittest related imports
import unittest

# ptf related imports
import ptf
import ptf.dataplane as dataplane
from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf import config

# framework related imports
import common.utils.p4rtctl_utils as p4rt_ctl
import common.utils.test_utils as test_utils
from common.utils.config_file_utils import (
    get_config_dict,
    get_gnmi_params_simple,
    get_interface_ipv4_dict,
)
from common.utils.gnmi_ctl_utils import gnmi_ctl_set_and_verify, ip_set_ipv4
import common.utils.log as log


class L2_Exact_Match(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)
        self.result = unittest.TestResult()
        config["relax"] = True

        test_params = test_params_get()
        config_json = test_params["config_json"]
        self.dataplane = ptf.dataplane_instance
        ptf.dataplane_instance = ptf.dataplane.DataPlane(config)

        self.config_data = get_config_dict(config_json)

        self.gnmictl_params = get_gnmi_params_simple(self.config_data)
        self.interface_ip_list = get_interface_ipv4_dict(self.config_data)

    def runTest(self):
        # Compile p4 file using p4c compiler and generate binary using ovs pipeline builder
        if not test_utils.gen_dep_files_p4c_tdi_pipeline_builder(self.config_data):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to generate P4C artifacts or pb.bin")

        # Create Ports using gnmi-ctl
        if not gnmi_ctl_set_and_verify(self.gnmictl_params):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to configure gnmi ctl ports")

        ip_set_ipv4(self.interface_ip_list)

        port_list = self.config_data["port_list"]
        port_ids = test_utils.add_port_to_dataplane(port_list)

        for port_id, ifname in config["port_map"].items():
            device, port = port_id
            self.dataplane.port_add(ifname, device, port)
        # Run Set-pipe command for set pipeline
        if not p4rt_ctl.p4rt_ctl_set_pipe(
            self.config_data["switch"],
            self.config_data["pb_bin"],
            self.config_data["p4_info"],
        ):
            self.result.addFailure(self, sys.exc_info())
            self.fail("Failed to set pipe")

        # Add rules for l2_exact match p4 program
        for table in self.config_data["table"]:
            log.info(f"Scenario : l2 exact match : {table['description']}")
            log.info(f"Adding {table['description']} rules")
            for match_action in table["match_action"]:
                if not p4rt_ctl.p4rt_ctl_add_entry(
                    table["switch"], table["name"], match_action
                ):
                    self.result.addFailure(self, sys.exc_info())
                    self.fail(f"Failed to add table entry {match_action}")

            # forming 1st packet and sending to validate if scenario-1:rule-1 hits or not
            log.info("sending packet to check if rule 1  hits")
            if table["description"] == "table_for_dst_mac":
                pkt = simple_tcp_packet(
                    eth_dst=self.config_data["traffic"]["in_pkt_header"]["eth_dst_1"]
                )
            else:
                pkt = simple_tcp_packet(
                    eth_src=self.config_data["traffic"]["in_pkt_header"]["eth_src_1"]
                )

            # Verify whether packet is received as per rule 1
            send_packet(
                self, port_ids[self.config_data["traffic"]["send_port"][0]], pkt
            )
            try:
                verify_packet(
                    self,
                    pkt,
                    port_ids[self.config_data["traffic"]["receive_port"][0]][1],
                )
                log.passed(
                    f"Verification of packets passed, packet received as per rule 1"
                )
            except Exception as err:
                self.result.addFailure(self, sys.exc_info())
                log.failed(f"Verification of packets sent failed with exception {err}")

            # forming 2th packet and sending to validate if scenario-1:rule-2 hits or not
            log.info("sending packet to check if rule2 hits")
            if table["description"] == "table_for_dst_mac":
                pkt = simple_tcp_packet(
                    eth_dst=self.config_data["traffic"]["in_pkt_header"]["eth_dst_2"]
                )
            else:
                pkt = simple_tcp_packet(
                    eth_src=self.config_data["traffic"]["in_pkt_header"]["eth_src_2"]
                )
            # Verify whether packet is dropped as per rule 2
            send_packet(
                self, port_ids[self.config_data["traffic"]["send_port"][1]], pkt
            )
            try:
                verify_no_packet_any(
                    self,
                    pkt,
                    device_number=0,
                    ports=[port_ids[self.config_data["traffic"]["receive_port"][1]][1]],
                )
                log.passed(
                    f"Verification of packets passed, packet dropped as per rule 2"
                )
            except Exception as err:
                self.result.addFailure(self, sys.exc_info())
                log.failed(f"Verification of packets sent failed with exception {err}")

        self.dataplane.kill()

    def tearDown(self):
        log.info("Deleting rules")
        for table in self.config_data["table"]:
            log.info(f"Deleting {table['description']} rules")
            for del_action in table["del_action"]:
                p4rt_ctl.p4rt_ctl_del_entry(table["switch"], table["name"], del_action)

        if self.result.wasSuccessful():
            log.passed("Test has PASSED")
        else:
            log.failed("Test has FAILED")
