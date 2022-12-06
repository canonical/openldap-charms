# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# ldap.py

import logging
import subprocess

logger = logging.getLogger(__name__)

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd
from utils.filedata import FileData

class LdapServer:
    """Server to provide LDAP server charm all functionality needed."""

    packages = ["slapd", "ldap-utils", "sssd-ldap", "gnutls-bin", "ssl-cert"]
    systemd_services = ["slapd"]    

    def __init__(self):
        pass

    def disable(self):
        """Disable services."""

        for name in self.systemd_services:
            systemd.service_pause(name)

    def enable(self):
        """Enable services."""

        for name in self.systemd_services:
            systemd.service_resume(name)

    def install(self) -> None:
        """Install packages."""
        if self.packages:
            try:
                apt.update()
                for name in self.packages:
                    apt.add_package(name)
            except:
                raise Exception(f"failed to install package ({name})")

    def is_enabled(self):
        """Check enabled status of services."""

        if self.systemd_services:
            for name in self.systemd_services:
                if not systemd._systemctl("is-enabled", name, quiet=True):
                    return False

        return True

    def is_installed(self):
        """Check packages are installed."""

        if self.packages:
            for name in self.packages:
                if not self.apt.DebianPackage.from_installed_package(name).present:
                    return False

        return True

    def is_running(self):
        """Check running/active status of services."""

        if self.systemd_services:
            for name in self.systemd_services:
                if not systemd.service_running(name):
                    return False

        return True

    def restart(self):
        """Restart servers/services."""

        self.stop()
        self.start()

    def start(self):
        """Start services."""

        for name in self.systemd_services:
            systemd.service_start(name)

    def stop(self):
        """Stop services."""

        for name in self.systemd_services:
            systemd.service_stop(name)

    def tls_deb(self):
        """Configuration of slapd noninteractive."""

        rc = subprocess.call(["export", "DEBIAN_FRONTEND=noninteractive"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, shell=True)
        if rc != 0:
                raise Exception(f"Unable to export.")

        args = [
            ["echo", "slapd slapd/no_configuration boolean false", "|", "debconf-set-selections"],
            ["echo", "slapd slapd/domain string lxd", "|", "debconf-set-selections"],
            ["echo", "slapd shared/organization string `lxd`", "|", "debconf-set-selections"],
            ["echo", "slapd slapd/password1 string `test`", "|", "debconf-set-selections"],
            ["echo", "slapd slapd/password1 string `test`", "|", "debconf-set-selections"],
            ["echo", "slapd slapd/purge_database boolean true", "|", "debconf-set-selections"],
            ["echo", "slapd slapd/move_old_database boolean true", "|", "debconf-set-selections"],
            ["dpkg-reconfigure", "-f", "noninteractive", "slapd"]
        ]

        for arg in args:
            rc = subprocess.call(arg, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception(f"Unable to run {arg[0]}")
    
    def tls_gen(self):
        """Create CA cert."""

        # Create Private Key for Certificate Authority(CA)
        pkc_args = ["certtool", "--generate-privkey", "--bits", "4096", "--outfile", "/etc/ssl/private/mycakey.pem"]
        rc = subprocess.call(pkc_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to create private key.")

        # CA Template
        ca_template = ["cn = HPC", "ca", "cert_signing_key", "expiration_days = 3650"]
        with open("/etc/ssl/ca.info", "w") as f:
            for l in ca_template:
                f.write(f"{l}\n")

        # Create CA Certificate
        ca_cert_args = ["certtool", "--generate-self-signed", "--load-privkey", "/etc/ssl/private/mycakey.pem", "--template", "/etc/ssl/ca.info",
                        "--outfile", "/usr/local/share/ca-certificates/mycacert.crt"]

        rc = subprocess.call(ca_cert_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to create certificate authority.")

        # Add CA certificate to trusted certs
        rc = subprocess.call(["update-ca-certificates"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to add CA certificate to trusted certs")
        
        # Get Server Hostname
        result = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True)

        # Private Key for Server
        pks_args = ["certtool", "--generate-privkey", "--bits", "2048", "--outfile", "/etc/ldap/ldap01_slapd_key.pem"]
        rc = subprocess.call(pks_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to create private key for server.")

        # Template for Server Certificate
        sc_template = ["organization = HPC", f"cn = {result.stdout}", "tls_www_server", "encryption_key", "signing_key", "expiration_days = 365"]
        with open("/etc/ssl/ldap01.info", "w") as f:
            for l in sc_template:
                f.write(f"{l}\n")

        # Create Server Certificate
        sc_args = ["certtool", "--generate-certificate", "--load-privkey", "/etc/ldap/ldap01_slapd_key.pem",
                   "--load-ca-certificate", "/etc/ssl/certs/mycacert.pem", "--load-ca-privkey",
                   "/etc/ssl/private/mycakey.pem", "--template", "/etc/ssl/ldap01.info", "--outfile", "/etc/ldap/ldap01_slapd_cert.pem"]
        rc = subprocess.call(sc_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to create server certificate.")
        
        # Adjust Permissions and Ownership
        g_args = ["chgrp", "openldap", "/etc/ldap/ldap01_slapd_key.pem"]
        rc = subprocess.call(g_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to set group permissions.")

        o_args = ["chmod", "0640", "/etc/ldap/ldap01_slapd_key.pem"]
        rc = subprocess.call(o_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to set owner permissions.")
        
        # Server Certificates LDIF
        sc_ldif = ["dn: cn=config", "add: olcTLSCACertificateFile", "olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem", 
                   "-", "add: olcTLSCertificateFile", "olcTLSCertificateFile: /etc/ldap/ldap01_slapd_cert.pem", "-",
                   "add: olcTLSCertificateKeyFile", "olcTLSCertificateKeyFile: /etc/ldap/ldap01_slapd_key.pem"]
        with open("/etc/ldap/certinfo.ldif", "w") as f:
            for l in sc_ldif:
                f.write(f"{l}\n")

        # Apply Certificate LDIF
        # ldif_args = ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/etc/ldap/certinfo.ldif"]
        # TODO: Won't work till `dpkg-reconfigure slapd` is done
        # rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        # if rc != 0:
        #    raise Exception("Unable to apply Server Certificate LDIF")

    def tls_load(self):
        """Load and return CA cert and ldap uri."""# Apply Certificate LDIF

        ldif_args = ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/etc/ldap/certinfo.ldif"]
        # Won't work till `dpkg-reconfigure slapd` is done
        rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to apply Server Certificate LDIF. Run `sudo dpkg-reconfigure slapd` first.")

        # sssd conf template for clients
        ldap_uri = result = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True)
        sssd_conf = [
            "[sssd]", "config_file_version = 2", "domains = lxd", "", "[domain/lxd]",
            "id_provider = ldap", "auth_provider = ldap", f"ldap_uri = ldap://{ldap_uri.stdout}",
            "cache_credentials = True", "ldap_search_base = dc=lxd"
        ]
        with open("/etc/sssd/sssd_conf.template", "w") as f:
            for l in sssd_conf:
                f.write(f"{l}\n")

        fd = FileData()
        fd.load("/etc/sssd/sssd_conf.template")
        sssd_conf = fd._dumps()
        fd.load("/usr/local/share/ca-certificates/mycacert.crt")
        ca_cert = fd._dumps()

        return ca_cert, sssd_conf
