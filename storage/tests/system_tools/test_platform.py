# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

import re

from system_tools.config import HostConfig, LpConfig, DockerConfig
from system_tools.const import ACC_INTERNAL_IP, LP_INTERNAL_IP
from system_tools.errors import MissingDependencyException
from system_tools.log import logging
from system_tools.terminals import DeviceTerminal, SSHTerminal
from system_tools.vm import VirtualMachine
from system_tools.errors import CommandException


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
        # self.docker = Docker(terminal)
        self._install_kernel_headers()

    def _install_kernel_headers(self):
        logging.ptf_info(f"Start installing kernel headers")
        raw = self.terminal.execute("sudo dnf install -y kernel-headers")
        logging.ptf_info(f"Kernel headers installed")
        return raw

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

    def _install_libguestfs_tools(self) -> bool:
        """Installs libguestfs-tools for a specific OS"""

        program = (
            "libguestfs-tools" if self.system == "ubuntu" else "libguestfs-tools-c"
        )
        out = self.terminal.execute(f"sudo {self.pms} install -y {program}")
        return bool(out)

    def _install_wget(self) -> bool:
        out = self.terminal.execute(f"sudo {self.pms} install -y wget")
        return bool(out)

    def _change_vmlinuz(self) -> bool:
        """Changes the mode of /boot/vmlinuz-*"""

        _, stdout, stderr = self.terminal.client.exec_command(
            "sudo chmod +r /boot/vmlinuz-*"
        )
        return not stdout.read().decode() or stderr.read().decode()

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

    # TODO add implementation
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
        env = f'''[Service]\n''' \
              f'''Environment="HTTP_PROXY="{docker_config.http_proxy}"\n''' \
              f'''Environment="HTTPS_PROXY={docker_config.https_proxy}"\n''' \
              f'''Environment="http_proxy={docker_config.http_proxy}"\n''' \
              f'''Environment="https_proxy={docker_config.https_proxy}"\n''' \
              f'''Environment="FTP_PROXY={docker_config.ftp_proxy}"\n''' \
              f'''Environment="ftp_proxy={docker_config.ftp_proxy}"'''
        self.terminal.execute(f"""echo -e '{env}' | sudo tee {filepath}""")
        self.terminal.execute("sudo systemctl daemon-reload")
        self.terminal.execute("sudo systemctl restart docker")
        # cgroups
        try:
            self.terminal.execute("sudo mkdir /sys/fs/cgroup/systemd")
            self.terminal.execute("sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd")
        except CommandException:
            pass

        logging.ptf_info(f"Docker service is setting")

    def _install_spdk_prerequisites(self):
        logging.ptf_info(f"Install spdk prerequisites")
        self.terminal.execute("cd spdk && sudo ./scripts/pkgdep.sh")
        self.terminal.execute("cd spdk && sudo ./configure --with-vfio-user")
        self.terminal.execute("cd spdk && sudo make")
        logging.ptf_info(f"spdk prerequisites installed")

    def _run_kvm_server(self):
        logging.ptf_info(f"Run kvm server")
        self.terminal.execute("sudo dnf install -y go")
        cmd = "go run ./cmd -ctrlr_dir=/var/tmp -kvm -port 50052 &"
        self.terminal.execute(f"cd opi-spdk-bridge && sudo {cmd}")
        logging.ptf_info(f"kvm server running")

    def _run_spdk_sock(self):
        logging.ptf_info("Run spdk sock")
        self.terminal.execute("sudo ./spdk/build/bin/spdk_tgt -S /var/tmp -s 1024 -m 0x3")

    def _run_second_spdk_sock(self):
        logging.ptf_info("Run second spdk sock")
        self.terminal.execute("sudo ./spdk/build/bin/spdk_tgt -S /var/tmp -s 1024 -m 0x20 -r /var/tmp/spdk2.sock")

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
        #self.clone()
        #if not self._is_docker():
        #self._install_docker()
        #self._set_docker()
        #self._install_spdk_prerequisites()
        #self._run_kvm_server()
        #self.create_hugepages()
        #self._run_spdk_sock()
        #self._run_second_spdk_sock()
        #self._create_transports()

        # todo nvme
        self.set_internal_ips()

    def clone(self):
        self.terminal.execute("git clone https://github.com/spdk/spdk --recursive")
        self.terminal.execute("git clone https://github.com/opiproject/opi-api")
        self.terminal.execute("git clone https://github.com/opiproject/opi-intel-bridge")
        self.terminal.execute("git clone https://github.com/opiproject/opi-spdk-bridge")
        self.terminal.execute("git clone https://github.com/ipdk-io/ipdk")

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

    def set_internal_ips(self):
        logging.ptf_info(f"Start setting internal ips")
        if self._is_lp_and_acc_ip_correct():
            logging.ptf_info(f"Internal ips is setting correctly")
            return True
        self.imc_device.execute("python3 /usr/bin/scripts/cfg_acc_apf_x2.py", 10)
        self.acc_device.execute("systemctl stop NetworkManager")

        lp_interfaces = [
            interface
            for interface in self._get_network_interfaces_names()
            if interface != "lo"
        ]
        acc_interfaces = [
            interface
            for interface in self._get_acc_network_interfaces_names()
            if interface != "lo"
        ]

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
        # TODO delete all alocated devices
        self.terminal.execute("rm -rf spdk")
        self.terminal.execute("rm -rf opi-api")
        self.terminal.execute("rm -rf opi-intel-bridge")
        self.terminal.execute("rm -rf opi-spdk-bridge")
        self.terminal.execute("rm -rf ipdk")
        return super().clean()


class HostPlatform(BaseTestPlatform):
    def __init__(self):
        super().__init__(SSHTerminal(HostConfig()))
        self.vm = None

    def set(self, run_vm=False):
        if run_vm:
            self.vm = VirtualMachine(self)
            self.vm.run("root", "root")

    def get_number_of_virtio_blk_devices(self):
        pass

    def host_target_service_port_in_vm(self):
        pass

    def get_service_address(self):
        pass

    def check_block_devices(self):
        pass

    def check_nvme_dev_files(self):
        pass


class PlatformFactory:
    def __init__(self):
        self.lp_platform = LinkPartnerPlatform()
        #self.host_platform = HostPlatform()

    def get_host_platform(self):
        return self.host_platform

    def get_lp_platform(self):
        return self.lp_platform
