# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

import re
import time

from system_tools.config import DockerConfig, HostConfig, LpConfig
from system_tools.const import (ACC_INTERNAL_IP, CONTROLLERS_NUMBER,
                                LP_INTERNAL_IP, SPDK_BDEV_BASE,
                                SPDK_BDEV_BLOCK_SIZE, SPDK_BDEV_NUM_BLOCKS,
                                SPDK_REP, SPDK_SNQN_BASE, SPDK_VERSION)
from system_tools.errors import CommandException, MissingDependencyException
from system_tools.log import logging
from system_tools.terminals import DeviceTerminal, SSHTerminal
from system_tools.vm import VirtualMachine


class RemoteNvmeStorage:
    """Helper class
    self.guid: volume_id
    self.nqn: subsystem nqn
    Malloc
    """

    def __init__(self, ip_address, port, nqn, guid):
        self.nvme_controller_address = ServiceAddress(ip_address, port)
        self.guid = guid
        self.nqn = nqn


class ServiceAddress:
    """storage_target_ip + vm_port(50051)"""

    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = port


class IpuStorageDevice:
    def __init__(
        self,
        device_handle,
        remote_nvme_storage,
        ipu_platform,
        host_target_address_service,
    ):
        self._device_handle = device_handle  # eg. nvme0
        self._remote_nvme_storage = remote_nvme_storage
        self._ipu_platform = ipu_platform
        self._host_target_address_service = host_target_address_service

    def run_fio(self, fio_args):
        return self._ipu_platform.run_fio(
            self._host_target_address_service.ip_address,
            self._device_handle,
            fio_args,
        )


class VirtioBlkDevice(IpuStorageDevice):
    def delete(self, cmd_sender):
        return cmd_sender.delete_virtio_blk_device(
            self._ipu_platform.get_ip_address(),
            self._host_target_address_service,
            self._device_handle,
            self._ipu_platform.sma_port,
        )


class NvmeDevice(IpuStorageDevice):
    def delete(self, cmd_sender):
        return cmd_sender.delete_virtio_blk_device(
            self._ipu_platform.get_ip_address(),
            self._host_target_address_service,
            self._device_handle,
            self._ipu_platform.sma_port,
        )

    def attach_volume(self, cmd_sender, storage_target_ip, nvme_port):
        return cmd_sender.attach_device(
            self._ipu_platform.get_ip_address(),
            storage_target_ip,
            self._device_handle,  # nvme0
            self._remote_nvme_storage.guid,  # malloc0
            nvme_port,
        )

    def detach_volume(self, cmd_sender):
        return cmd_sender.detach_volume(
            self._ipu_platform.get_ip_address(),
            self._device_handle,
            self._remote_nvme_storage.guid,
        )

    def delete_device(self, cmd_sender):
        return cmd_sender.delete_device(
            self._ipu_platform.get_ip_address(),
            self._host_target_address_service.ip_address,
            self._device_handle,
            self._ipu_platform.sma_port,
            self._host_target_address_service.port,
        )


class BaseTestPlatform:
    """A base class used to represent operating system with needed libraries"""

    def __init__(self, terminal):
        self.terminal = terminal
        self.config = self.terminal.config
        self.pms = "dnf" if self._is_dnf() else "apt-get" if self._is_apt() else None
        self.system = self._os_system()
        self._install_kernel_headers()

    def change_cpu_performance_scaling(self):
        try:
            for i in range(int(self.terminal.execute("nproc"))):
                freq = self.terminal.execute(
                    f"cat /sys/devices/system/cpu/cpu{i}/cpufreq/cpuinfo_max_freq"
                )
                scaling_max_freq = (
                    f"/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_max_freq"
                )
                self.terminal.execute(
                    f"""echo -e '{freq}' | sudo tee {scaling_max_freq}"""
                )
                scaling_min_freq = (
                    f"/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_min_freq"
                )
                self.terminal.execute(
                    f"""echo -e '{freq}' | sudo tee {scaling_min_freq}"""
                )

                scaling_governor = (
                    f"/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_governor"
                )
                self.terminal.execute(
                    f"""echo -e performance | sudo tee {scaling_governor}"""
                )
                energy_performance_preference = f"/sys/devices/system/cpu/cpu{i}/cpufreq/energy_performance_preference"
                self.terminal.execute(
                    f"""echo -e performance | sudo tee {energy_performance_preference}"""
                )
        except CommandException:
            logging.error(f"If permission denied or file not exist is ok")

    def _install_kernel_headers(self):
        logging.ptf_info(f"Start installing kernel headers")
        raw = self.terminal.execute("sudo dnf install -y kernel-headers")
        logging.ptf_info(f"Kernel headers installed")
        return raw

    def get_cpus_to_use(self):
        node = 1
        try:
            logging.ptf_info(f"Start get cpus to use")
            node_cpus = self.terminal.execute(
                f"""numactl --cpunodebind {node} --show | grep physcpubind"""
            ).split()
            return [int(cpu) for cpu in node_cpus[1:17]]  # first 16 cpus
        except CommandException:
            logging.error(f"export CPUS_TO_USE")

    def get_ip_address(self):
        return self.config.ip_address

    def get_storage_dir(self):
        return self.config.storage_dir

    def _os_system(self) -> str:
        return self.terminal.execute("sudo cat /etc/os-release | grep ^ID=")[3:]

    def _is_dnf(self) -> bool:
        _, stdout, _ = self.terminal.client.exec_command("dnf --version")
        return not stdout.channel.recv_exit_status()

    def _is_apt(self) -> bool:
        _, stdout, _ = self.terminal.client.exec_command("apt-get --version")
        return not stdout.channel.recv_exit_status()

    def _is_docker(self) -> bool:
        _, stdout, _ = self.terminal.client.exec_command("docker --version")
        return not stdout.channel.recv_exit_status()

    def _is_virtualization(self) -> bool:
        """Checks if VT-x/AMD-v support is enabled in BIOS"""

        expectations = ["vt-x", "amd-v", "full"]
        out = self.terminal.execute("lscpu | grep -i virtualization")
        for allowed_str in expectations:
            if allowed_str.upper() in out.upper():
                return True
        return False

    def _is_kvm(self) -> bool:
        """Checks if kvm modules are loaded"""

        expectations = ["kvm_intel", "kvm_amd"]
        out = self.terminal.execute("lsmod | grep -i kvm")
        for allowed_str in expectations:
            if allowed_str.upper() in out.upper():
                return True
        return False

    # TODO add implementation
    def _is_qemu(self) -> bool:
        return True

    def _set_security_policies(self) -> bool:
        cmd = (
            "sudo setenforce 0"
            if self.system == "fedora"
            else "sudo systemctl stop apparmor"
        )
        _, stdout, stderr = self.terminal.client.exec_command(cmd)
        return (
            "disabled" in stdout.read().decode() or "disabled" in stderr.read().decode()
        )

    def _install_docker(self):
        logging.ptf_info(f"Start installing docker")
        return self.terminal.execute("sudo dnf install -y docker")
        logging.ptf_info(f"Docker is installed")

    def _set_docker(self):
        docker_config = DockerConfig()
        filepath = "/etc/systemd/system/docker.service.d/http-proxy.conf"
        logging.ptf_info(f"Start setting docker service")
        self.terminal.execute("sudo mkdir -p /etc/systemd/system/docker.service.d")
        # proxies
        env = (
            f"""[Service]\n"""
            f"""Environment="HTTP_PROXY="{docker_config.http_proxy}"\n"""
            f"""Environment="HTTPS_PROXY={docker_config.https_proxy}"\n"""
            f"""Environment="http_proxy={docker_config.http_proxy}"\n"""
            f"""Environment="https_proxy={docker_config.https_proxy}"\n"""
            f"""Environment="FTP_PROXY={docker_config.ftp_proxy}"\n"""
            f'''Environment="ftp_proxy={docker_config.ftp_proxy}"'''
        )
        self.terminal.execute(f"""echo -e '{env}' | sudo tee {filepath}""")
        self.terminal.execute("sudo systemctl daemon-reload")
        self.terminal.execute("sudo systemctl restart docker")
        # cgroups
        try:
            self.terminal.execute("sudo mkdir /sys/fs/cgroup/systemd")
            self.terminal.execute(
                "sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd"
            )
        except CommandException:
            pass

        logging.ptf_info(f"Docker service is setting")

    def _install_spdk_prerequisites(self):
        logging.ptf_info(f"Install spdk prerequisites")
        self.terminal.execute("cd spdk && sudo ./scripts/pkgdep.sh")
        self.terminal.execute("cd spdk && sudo ./configure --with-vfio-user")
        self.terminal.execute("cd spdk && sudo make")
        logging.ptf_info(f"spdk prerequisites installed")

    def _create_transports(self):
        logging.ptf_info(f"Create transports")
        directory = "cd spdk/scripts/"
        cmd1 = "./rpc.py -s /var/tmp/spdk2.sock nvmf_create_transport -t tcp"
        cmd2 = "./rpc.py -s /var/tmp/spdk2.sock nvmf_create_transport -t vfiouser"
        cmd3 = "./rpc.py nvmf_create_transport -t tcp"
        cmd4 = "./rpc.py nvmf_create_transport -t vfiouser"
        self.terminal.execute(f"cd {directory} && sudo {cmd1}")
        self.terminal.execute(f"cd {directory} && sudo {cmd2}")
        self.terminal.execute(f"cd {directory} && sudo {cmd3}")
        self.terminal.execute(f"cd {directory} && sudo {cmd4}")

    def check_system_setup(self):
        """Overwrite this method in specific platform if you don't want check all setup"""
        if not self._is_virtualization():
            raise MissingDependencyException("Virtualization may not be set properly")
        if not self._is_kvm():
            raise MissingDependencyException("KVM may not be set properly")
        if not self.pms:
            raise MissingDependencyException("Packet manager may not be installed")
        if not self._is_qemu():
            raise MissingDependencyException("QUEMU may not be set properly")
        if not self._set_security_policies():
            raise MissingDependencyException("Security polices may not be set properly")
        if not self._is_docker():
            raise MissingDependencyException("Docker may not be installed")

    def get_pid_from_port(self, port: int):
        return self.terminal.execute(
            f"sudo netstat -anop | grep -Po ':{port}\s.*LISTEN.*?\K\d+(?=/)' || true"
        )

    def path_exist(self, path):
        return self.terminal.execute(f"test -e {path} || echo False") != "False"

    def kill_process_from_port(self, port: int):
        """Raise error if there is no process occupying specific port"""
        pid = self.get_pid_from_port(port)
        self.terminal.execute(f"sudo kill -9 {pid}")

    def clean(self):
        pass

    def is_port_free(self, port):
        return not bool(
            self.terminal.execute(f"sudo netstat -anop | grep ':{port} ' || true")
        )

    def is_app_listening_on_port(self, app_name, port):
        out = self.terminal.execute(f"sudo netstat -anop | grep ':{port} ' || true")
        return "spdk_tgt" in out


class LinkPartnerPlatform(BaseTestPlatform):
    def __init__(self):
        super().__init__(SSHTerminal(LpConfig()))
        self.imc_device = DeviceTerminal(self.terminal, "/dev/ttyUSB2")
        self.acc_device = DeviceTerminal(self.terminal, "/dev/ttyUSB0")

    def set(self):
        self.imc_device.login()
        self.acc_device.login()
        self.set_internal_ips()
        self.change_cpu_performance_scaling()
        self.set_spdk()
        mask = self.find_spdk_mask()
        lp_rpc = "/home/berta/spdk/scripts/rpc.py"
        self.set_nvmf_tgt(mask, lp_rpc)
        self.create_devices(lp_rpc)
        self.prepare_acc()
        acc_rpc = "/opt/ssa/rpc.py"
        self.start_ssa(acc_rpc)
        self.run_npi_transport(acc_rpc)
        self.create_pf_device(acc_rpc)
        self.create_subsystems(acc_rpc, CONTROLLERS_NUMBER)
        self.create_controllers(acc_rpc, CONTROLLERS_NUMBER)
        self.add_remote_controllers(acc_rpc, CONTROLLERS_NUMBER)
        self.create_namespaces(acc_rpc, CONTROLLERS_NUMBER)

    def create_subsystems(self, rpc_path, num):
        time.sleep(5)
        try:
            logging.ptf_info(f"Create subsystems")
            for i in range(1, num + 1):
                self.terminal.execute(
                    f"ssh root@200.1.1.3 {rpc_path} nvmf_create_subsystem nqn.2019-07.io.spdk:npi-0.{i} -a"
                )
                time.sleep(2)
            logging.ptf_info(f"End creating subsystems")
        except CommandException:
            logging.error(f"Subsystems didn't create")

    def create_controllers(self, rpc_path, num):
        time.sleep(5)
        nvmf_queues = 25
        try:
            logging.ptf_info(f"Create controllers")
            for i in range(1, num + 1):
                self.terminal.execute(
                    f"ssh root@200.1.1.3 {rpc_path} --plugin npi nvmf_subsystem_add_listener -t npi -a 0.{i} nqn.2019-07.io.spdk:npi-0.{i} --max-qpairs {nvmf_queues}"
                )
                time.sleep(2)
            logging.ptf_info(f"End creating controllers")
        except CommandException:
            logging.error(f"Controllers didn't create")

    def add_remote_controllers(self, rpc_path, num):
        time.sleep(5)
        try:
            logging.ptf_info(f"Add remote controllers")
            for i in range(1, num + 1):
                self.terminal.execute(
                    f"ssh root@200.1.1.3 {rpc_path} bdev_nvme_attach_controller -b Nvme{i} -t TCP -a 200.1.1.1 -f IPv4 -s 4420 -n nqn.2019-06.io.spdk:{i}"
                )
                time.sleep(2)
            logging.ptf_info(f"End adding remote controllers")
        except CommandException:
            logging.error(f"Remote controllers didn't add")

    def create_namespaces(self, rpc_path, num):
        time.sleep(10)
        try:
            logging.ptf_info(f"Create namespaces")
            for i in range(1, num + 1):
                self.terminal.execute(
                    f"ssh root@200.1.1.3 {rpc_path} nvmf_subsystem_add_ns nqn.2019-07.io.spdk:npi-0.{i} Nvme{i}n1"
                )
                time.sleep(2)
            logging.ptf_info(f"End creating namespaces")
        except CommandException:
            logging.error(f"Namespaces didn't create")

    def create_pf_device(self, rpc_path):
        nvmf_queues = 25
        try:
            logging.ptf_info(f"Start create pf device")
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} nvmf_create_subsystem nqn.2019-07.io.spdk:npi-0.0 -a'"
            )
            time.sleep(5)
            cmd = (
                f"ssh root@200.1.1.3 '{rpc_path} --plugin npi nvmf_subsystem_add_listener"
                f" nqn.2019-07.io.spdk:npi-0.0 --trtype NPI --traddr 0.0 --max-qpairs {nvmf_queues}'"
            )
            self.terminal.execute(cmd)
            time.sleep(5)
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} bdev_null_create NullPF {SPDK_BDEV_NUM_BLOCKS} {SPDK_BDEV_BLOCK_SIZE}'"
            )
            time.sleep(5)
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} nvmf_subsystem_add_ns nqn.2019-07.io.spdk:npi-0.0  NullPF'"
            )
            time.sleep(5)
            logging.ptf_info(f"End create pf device")
        except CommandException:
            logging.error(f"Create PF device")

    def run_npi_transport(self, rpc_path):
        try:
            logging.ptf_info(f"Start run npi transport")
            cmd = (
                f"ssh root@200.1.1.3 'export MEV_NVME_DEVICE_MODE=HW_ACC_WITH_IMC "
                f"&& PYTHONPATH=/opt/ssa/rpc {rpc_path} --plugin npi nvmf_create_transport -t npi'"
            )
            self.terminal.execute(cmd)
            logging.ptf_info(f"End run npi transport")
        except CommandException:
            logging.error(f"Run NPI transport")

    def start_ssa(self, rpc_path):
        try:
            logging.ptf_info(f"Start SSA on ACC")
            self.terminal.execute(
                f"ssh root@200.1.1.3 'echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'"
            )
            cmd = (
                f"ssh root@200.1.1.3 'ssa --logflag dma_utils --logflag npi"
                f" --logflag nvme --logflag nvmf --logflag bdev_nvme -B 00:01.1 -m 0xEFFF --wait-for-rpc' &"
            )
            self.terminal.execute(cmd)
            time.sleep(10)
            logging.ptf_info(f"End start SSA on ACC")
            logging.ptf_info(f"Start set SSA")
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} sock_impl_set_options -iposix --enable-zerocopy-send-server'"
            )
            time.sleep(2)
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} iobuf_set_options --small-pool-count 12288 --large-pool-count 6144'"
            )
            time.sleep(2)
            self.terminal.execute(
                f"ssh root@200.1.1.3 '{rpc_path} framework_start_init'"
            )
            time.sleep(1)
            logging.ptf_info(f"End set SSA")
        except CommandException:
            logging.error(f"Start SSA on ACC")

    def prepare_acc(self):
        try:
            logging.ptf_info(f"Start prepare acc")
            self.terminal.execute(f"ssh root@200.1.1.3 modprobe -r qat_lce_cpfxx")
            self.terminal.execute(f"ssh root@200.1.1.3 modprobe qat_lce_cpfxx")
            cpfdev = self.terminal.execute(
                f"ssh root@200.1.1.3 lspci -D -d :1456 | cut -f1 -d' '"
            )
            mdev_uuid = self.terminal.execute(
                f"ssh root@200.1.1.3 cat /proc/sys/kernel/random/uuid"
            )
            cmd = (
                f"ssh root@200.1.1.3 'echo {mdev_uuid} >"
                f" /sys/bus/pci/devices/{cpfdev}/mdev_supported_types/lce_cpfxx-mdev/create'"
            )
            self.terminal.execute(cmd)

            path = f"/sys/bus/mdev/devices/{mdev_uuid}/"
            self.terminal.execute(f"ssh root@200.1.1.3 'echo 0 > {path}enable'")
            self.terminal.execute(
                f"ssh root@200.1.1.3 'echo 15 > {path}dma_queue_pairs'"
            )
            self.terminal.execute(
                f"ssh root@200.1.1.3 'echo 15 > {path}cy_queue_pairs'"
            )
            self.terminal.execute(f"ssh root@200.1.1.3 'echo 1 > {path}enable'")

            self.terminal.execute(
                f"ssh root@200.1.1.3 dma_sample 0"
            )  # test if DMA works
            self.terminal.execute(f"ssh root@200.1.1.3 modprobe vfio-pci")
            self.terminal.execute(f"ssh root@200.1.1.3 sysctl -w vm.nr_hugepages=2048")
            self.terminal.execute(
                f"ssh root@200.1.1.3 'echo 8086 1458 > /sys/bus/pci/drivers/vfio-pci/new_id'"
            )
            logging.ptf_info(f"End prepare acc")
        except CommandException:
            logging.error(f"ACC prepare commands")

    def create_devices(self, rpc_path):
        try:
            # create devices on lp
            logging.ptf_info(f"Start create devices on lp")
            for i in range(CONTROLLERS_NUMBER):
                self.terminal.execute(
                    f"sudo {rpc_path} bdev_null_create {SPDK_BDEV_BASE}{i} {SPDK_BDEV_NUM_BLOCKS} {SPDK_BDEV_BLOCK_SIZE}"
                )
                self.terminal.execute(
                    f"sudo {rpc_path} nvmf_create_subsystem {SPDK_SNQN_BASE}:{i+1} --allow-any-host --max-namespaces {CONTROLLERS_NUMBER}"
                )
                self.terminal.execute(
                    f"sudo {rpc_path} nvmf_subsystem_add_ns {SPDK_SNQN_BASE}:{i+1}  {SPDK_BDEV_BASE}{i}"
                )
                cmd = (
                    f"sudo {rpc_path} nvmf_subsystem_add_listener"
                    f" {SPDK_SNQN_BASE}:{i + 1} --trtype tcp --traddr 200.1.1.1 --trsvcid 4420"
                )
                self.terminal.execute(cmd)
            logging.ptf_info(f"End create devices on lp")
        except CommandException:
            logging.error(f"create devices on lp")

    def set_nvmf_tgt(self, mask, rpc_path):
        # Setup nvmf_tgt and create transport
        nr_hugepages = 2048
        try:
            logging.ptf_info(f"Start setup nvmf_tgt and create transport")
            self.terminal.execute(f"sudo sysctl -w vm.nr_hugepages={nr_hugepages}")
            self.terminal.execute(
                f"cd spdk && sudo ./build/bin/nvmf_tgt --cpumask {mask} --wait-for-rpc &"
            )
            self.terminal.execute(
                f"sudo {rpc_path} sock_impl_set_options -iposix --enable-zerocopy-send-server"
            )
            self.terminal.execute(
                f"sudo {rpc_path} iobuf_set_options --small-pool-count 12288 --large-pool-count 12288"
            )
            self.terminal.execute(f"sudo {rpc_path} framework_start_init")
            self.terminal.execute(
                f"sudo {rpc_path} nvmf_create_transport --trtype TCP --max-queue-depth=4096 --num-shared-buffers=8191"
            )
            logging.ptf_info(f"End setup nvmf_tgt and create transport")
        except CommandException:
            logging.error(f"Setup nvmf_tgt and create transport")

    def find_spdk_mask(self):
        cpus_to_use = self.get_cpus_to_use()
        try:
            logging.ptf_info(f"Start find mask for SPDK on LP")
            spdk_cpu_mask = 0
            for cpu in cpus_to_use:
                spdk_cpu_mask = self.terminal.execute(
                    f"echo $(({spdk_cpu_mask} | (1 << {cpu})))"
                )
            logging.ptf_info(f"End find mask for SPDK on LP")
            return hex(int(spdk_cpu_mask))
        except CommandException:
            logging.error(f"Find mask for SPDK on LP")

    def set_spdk(self):
        # Download and configure spdk on LP
        try:
            logging.ptf_info(f"Start set spdk")
            self.terminal.execute(SPDK_REP)
            self.terminal.execute(f"cd spdk && git checkout {SPDK_VERSION}")
            self.terminal.execute("cd spdk && git submodule update --init")
            self._install_spdk_prerequisites()
            logging.ptf_info(f"End set spdk")
        except CommandException:
            logging.error(f"Download and configure spdk on LP")

    def create_hugepages(self):
        self.terminal.execute(
            "sudo bash -c 'echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'"
        )

    def _get_network_interfaces_names(self):
        raw = self.terminal.execute("ip a")
        return re.findall("\d: (.*?):", raw)

    def _get_acc_network_interfaces_names(self):
        raw = self.acc_device.execute("ip a", 60)
        return re.findall("\d: (.*?):", raw)

    def _set_acc_ip(self, ip, interface):
        self.acc_device.execute(f"ip a add {ip} dev {interface}")
        self.acc_device.execute(f"ip link set dev {interface} up")

    def _unset_acc_ip(self, ip, interface):
        self.acc_device.execute(f"ip a del {ip} dev {interface}")
        self.acc_device.execute(f"ip link set dev {interface} up")

    def _set_ip(self, ip, interface):
        self.terminal.execute(f"sudo ip a add {ip} dev {interface}")
        self.terminal.execute(f"sudo ip link set dev {interface} up")

    def _unset_ip(self, ip, interface):
        self.terminal.execute(f"sudo ip a del {ip} dev {interface}")
        self.terminal.execute(f"sudo ip link set dev {interface} up")

    def _is_lp_and_acc_ip_correct(self):
        try:
            self.terminal.execute("ping -w 4 -c 2 200.1.1.3")
            return True
        except:
            return False

    def _get_valid_interfaces(self, interfaces):
        return [interface for interface in interfaces if interface != "lo"]

    def set_internal_ips(self):
        logging.ptf_info(f"Start setting internal ips")
        if self._is_lp_and_acc_ip_correct():
            logging.ptf_info(f"Internal ips is setting correctly")
            return True
        self.imc_device.execute("python3 /usr/bin/scripts/cfg_acc_apf_x2.py", 10)
        self.acc_device.execute("systemctl stop NetworkManager")
        lp_interfaces = self._get_valid_interfaces(self._get_network_interfaces_names())
        acc_interfaces = self._get_valid_interfaces(
            self._get_acc_network_interfaces_names()
        )
        for lp_interface in lp_interfaces:
            if not self._is_lp_and_acc_ip_correct():
                self._set_ip(LP_INTERNAL_IP, lp_interface)
            for acc_interface in acc_interfaces:
                if not self._is_lp_and_acc_ip_correct():
                    self._set_acc_ip(ACC_INTERNAL_IP, acc_interface)
                if not self._is_lp_and_acc_ip_correct():
                    self._unset_acc_ip(ACC_INTERNAL_IP, acc_interface)
            if not self._is_lp_and_acc_ip_correct():
                self._unset_ip(LP_INTERNAL_IP, lp_interface)
        end = self._is_lp_and_acc_ip_correct()
        if end:
            logging.ptf_info(f"Internal ips is setting correctly")
        else:
            logging.error(f"Internal ips is not setting correctly")
        return self._is_lp_and_acc_ip_correct()

    def create_subsystem(self, nqn: str, port_to_expose: int, storage_target_port: int):
        pass

    def create_ramdrives(self, ramdrives_number, port, nqn, spdk_port):
        pass

    @property
    def sma_port(self):
        return self.config.sma_port

    def run_fio(self, host_target_ip, device_handle, fio_args):
        pass

    def create_nvme_device(self, host_target_address_service, volume, num):
        pass

    def create_virtio_blk_devices(
        self,
        host_target_address_service,
        volumes,
        physical_ids,
    ):
        pass

    def create_virtio_blk_devices_sequentially(
        self,
        host_target_address_service,
        volumes,
    ):
        pass

    def create_nvme_devices_sequentially(
        self,
        host_target_address_service,
        volumes,
    ):
        pass

    def delete_virtio_blk_devices(self, devices_handles):
        pass

    def clean(self):
        self.terminal.execute("sudo rm -rf spdk")
        return super().clean()


class HostPlatform(BaseTestPlatform):
    def __init__(self):
        super().__init__(SSHTerminal(HostConfig()))
        self.vm = None

    def set(self, run_vm=False):
        nvme_pf_bdf = self.get_nvme_pf_bdf()
        self.bind_pf(nvme_pf_bdf)
        self.create_vfs(nvme_pf_bdf)
        self.bind_vfs(nvme_pf_bdf)
        if run_vm:
            self.vm = VirtualMachine(self)
            self.vm.run("root", "root")

    def get_nvme_pf_bdf(self):
        # On SUT find the address of PF
        pfs = self.terminal.execute(f"""lspci -D -d 8086:1457 | cut -d " " -f1""")
        return pfs.split("\n")[0]

    def bind_pf(self, nvme_pf_bdf):
        logging.ptf_info(f"PF binding")
        return self.terminal.execute(
            f"""echo {nvme_pf_bdf} | sudo tee /sys/bus/pci/drivers/nvme/bind"""
        )

    def create_vfs(self, nvme_pf_bdf):
        logging.ptf_info(f"Create VFs on SUT")
        filepath = f"/sys/bus/pci/devices/{nvme_pf_bdf}/sriov_drivers_autoprobe"
        self.terminal.execute(f"""echo 0 | sudo tee {filepath}""")
        filepath = f"/sys/bus/pci/drivers/nvme/{nvme_pf_bdf}/sriov_numvfs"
        self.terminal.execute(f"""echo {CONTROLLERS_NUMBER} | sudo tee {filepath}""")
        logging.ptf_info(f"End creating VFs on SUT")

    def bind_vfs(self, nvme_pf_bdf):
        logging.ptf_info(f"Bind VFs to NVMe driver")
        for i in range(CONTROLLERS_NUMBER):
            filepath = f"/sys/bus/pci/devices/{nvme_pf_bdf}/virtfn{i}/driver_override"
            self.terminal.execute(f"""echo nvme | sudo tee {filepath}""")
            filepath = f"/sys/bus/pci/drivers/nvme/bind"
            virtfn = self.terminal.execute(
                f"""echo $(basename "$(realpath "/sys/bus/pci/devices/{nvme_pf_bdf}/virtfn{i}")")"""
            )
            self.terminal.execute(f"""echo {virtfn} | sudo tee {filepath}""")
            time.sleep(10)
        logging.ptf_info(f"End binding VFs to NVMe driver")

    def run_performance_fio(self):
        logging.ptf_info(f"Start fio")
        cpus_to_use = self.get_cpus_to_use()
        filenames = ""
        for i in range(2, CONTROLLERS_NUMBER + 2):
            filenames = filenames + f"--filename=/dev/nvme{i}n1 "
        fio = f"""
        sudo taskset -c {cpus_to_use[0]}-{cpus_to_use[-1]} fio --name=test --rw=randwrite {filenames}\
        --numjobs=12 --group_reporting --runtime=20 --time_based=1 --io_size=4096 --iodepth=2048 --ioengine=libaio --ramp_time 5
        """
        response = self.terminal.execute(f"{fio}")
        logging.ptf_info(f"End fio")
        return response


class PlatformFactory:
    def __init__(self):
        self.lp_platform = LinkPartnerPlatform()
        self.host_platform = HostPlatform()

    def get_host_platform(self):
        return self.host_platform

    def get_lp_platform(self):
        return self.lp_platform
