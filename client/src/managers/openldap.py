#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# managers/ldap.py
"""Manager for client operator."""
import logging

logger = logging.getLogger(__name__)
import subprocess

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from utils.filedata import FileData


class OpenldapClientManager:
    """Manager to provide LDAP client charm all functionality needed."""

    packages = ["ldap-utils", "sssd-ldap"]
    systemd_services = ["sssd"]

    def __init__(self):
        pass

    def disable(self) -> None:
        """Disable services."""
        for name in self.systemd_services:
            systemd.service_pause(name)

    def enable(self) -> None:
        """Enable services."""
        for name in self.systemd_services:
            systemd.service_resume(name)

    def install(self) -> None:
        """Install using charmlib apt."""
        if self.packages:
            try:
                apt.update()
                for name in self.packages:
                    apt.add_package(name)
            except:
                raise Exception(f"failed to install package ({name})")

    def is_enabled(self) -> bool:
        """Check enabled status of services."""
        if self.systemd_services:
            for name in self.systemd_services:
                if not systemd._systemctl("is-enabled", name, quiet=True):
                    return False

        return True

    def is_installed(self) -> bool:
        """Check packages are installed."""
        if self.packages:
            for name in self.packages:
                try:
                    if not apt.DebianPackage.from_installed_package(name).present:
                        return False
                except:
                    return False
        return True

    def is_running(self) -> bool:
        """Check running/active status of services."""
        if self.systemd_services:
            for name in self.systemd_services:
                if not systemd.service_running(name):
                    return False

        return True

    def restart(self) -> None:
        """Restart servers/services."""
        self.stop()
        self.start()

    def save_ca_cert(self, ca_cert):
        """Save CA certificate.

        Parameters
        ----------
        ca_cert : str
            CA certificate.
        """
        fd = FileData(ca_cert)
        fd.save("/usr/local/share/ca-certificates/mycacert.crt")

        rc = subprocess.call(
            ["update-ca-certificates"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        if rc != 0:
            raise Exception("Unable to update ca certificates.")

    def save_sssd_conf(self, sssd_conf):
        """Save sssd conf.

        Parameters
        ----------
        sssd_conf : str
            SSSD configuration file.
        """
        fd = FileData(sssd_conf)
        fd.save("/etc/sssd/sssd.conf", mode=0o600, owner="root", group="root")

        systemd.service_restart("sssd")

    def start(self) -> None:
        """Start services."""
        for name in self.systemd_services:
            systemd.service_start(name)

    def stop(self) -> None:
        """Stop services."""
        for name in self.systemd_services:
            systemd.service_stop(name)
