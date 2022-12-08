# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# servers/ldap.py

import logging
import subprocess
import tempfile

logger = logging.getLogger(__name__)

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from utils.filedata import FileData

MIN_GID = 999
MIN_UID = 999


class LdapServer:
    """Server to provide LDAP server charm all functionality needed."""
    packages = ["slapd", "ldap-utils", "sssd-ldap", "gnutls-bin", "ssl-cert"]
    systemd_services = ["slapd"]

    def __init__(self):
        pass

    def _add_base(self, dcs, passwd) -> None:
        """Define base for groups and users.

        Parameters
        ----------
        dcs : str
            Domain components.
        passwd : str
            LDAP password.
        """
        base = [
            f"dn: ou=People,{dcs}",
            "objectClass: organizationalUnit",
            "ou: People",
            "",
            f"dn: ou=Groups,{dcs}",
            "objectClass: organizationalUnit",
            "ou: Groups",
        ]

        with open("/etc/ldap/basedn.ldif", "w") as f:
            for line in base:
                f.write(f"{line}\n")

        binddn = f"cn=admin,{dcs}"
        cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", "/etc/ldap/basedn.ldif"]

        rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if rc != 0:
            raise Exception("Unable to add basedn ldif.")

    def _split_domain(self, dc) -> str:
        """Split domain components.

        Parameters
        ----------
        dcs : str
            Domain components.
        """
        if "." in dc:
            split_dc = []
            dcs = dc.split(".")
            for d in dcs:
                if len(d) < 1:
                    raise Exception("Invalid domain components given, cannot be empty.")
                else:
                    split_dc.append(f"dc={d}")
            return ",".join(split_dc)
        else:
            return f"dc={dc}"

    def add_user(
        self, domain=None, gid=None, passwd=None, uid=None, upasswd=None, user=None
    ) -> None:
        """Add user.

        Parameters
        ----------
        domain : str
            Domain name.
        gid : int
            Group id.
        passwd : str
            LDAP password.
        uid : int
            User id.
        upasswd : str
            User password.
        user : str
            Username.
        """
        dcs = self._split_domain(domain)

        if None not in [dcs, gid, passwd, uid, upasswd, user] and uid > MIN_UID and gid > MIN_GID:
            binddn = f"cn=admin,{dcs}"
            base_user = [
                f"dn: uid={user.lower()},ou=people,{dcs}",
                "objectClass: inetOrgPerson",
                "objectClass: posixAccount",
                "objectClass: shadowAccount",
                f"cn: {user.lower()}",
                f"sn: {user}",
                f"userPassword: {upasswd}",
                "loginShell: /bin/bash",
                f"uidNumber: {uid}",
                f"gidNumber: {gid}",
                f"homeDirectory: /home/{user.lower()}",
            ]

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                for line in base_user:
                    f.write(f"{line}\n")
                    f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add user. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

    def add_group(self, domain=None, gid=None, group=None, passwd=None) -> None:
        """Add group.

        Parameters
        ----------
        domain : str
            Domain name.
        gid : int
            Group id.
        group : str
            Group name.
        passwd : str
            LDAP password.
        """
        dcs = self._split_domain(domain)

        if None not in [domain, gid, group, passwd] and gid > MIN_GID:
            binddn = f"cn=admin,{dcs}"
            base_group = [
                f"dn: cn={group},ou=Groups,{dcs}",
                "objectClass: posixGroup",
                f"cn: {group}",
                f"gidNumber: {gid}",
            ]

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                for line in base_group:
                    f.write(f"{line}\n")
                    f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add group. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

    def disable(self) -> None:
        """Disable services."""
        for name in self.systemd_services:
            systemd.service_pause(name)

    def enable(self) -> None:
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
                if not self.apt.DebianPackage.from_installed_package(name).present:
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

    def set_config(self, domain=None, org=None, passwd=None) -> None:
        """Set LDAP password and slapd configuration.

        Parameters
        ----------
        domain : str
            Domain name.
        org : str
            Organization name.
        passwd : str
            LDAP password.
        """
        if domain and org and passwd:
            dcs = self._split_domain(domain)

            # Reconfigure slapd with password
            self.tls_deb(domain, org, passwd)
            self._add_base(dcs, passwd)
        else:
            raise Exception("Domain, Organization, or Password is missing cannot complete action.")

    def start(self) -> None:
        """Start services."""
        for name in self.systemd_services:
            systemd.service_start(name)

    def stop(self) -> None:
        """Stop services."""
        for name in self.systemd_services:
            systemd.service_stop(name)

    def tls_deb(self, domain, org, passwd) -> None:
        """Configuration of slapd noninteractive.

        Parameters
        ----------
        domain : str
            Domain name.
        org : str
            Organization name.
        passwd : str
            LDAP password.
        """
        args = [
            "slapd slapd/no_configuration boolean false",
            f"slapd slapd/domain string {domain}",
            f"slapd shared/organization string {org}",
            f"slapd slapd/password1 password {passwd}",
            f"slapd slapd/password2 password {passwd}",
            "slapd slapd/purge_database boolean true",
            "slapd slapd/move_old_database boolean true",
        ]

        with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
            for arg in args:
                f.write(f"{arg}\n")
                f.flush()

            ps = subprocess.Popen(("cat", f"{f.name}"), stdout=subprocess.PIPE)
            output = subprocess.check_output(("debconf-set-selections"), stdin=ps.stdout)
            ps.wait()

        rc = subprocess.call(
            ["dpkg-reconfigure", "-f", "noninteractive", "slapd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        if rc != 0:
            raise Exception(f"Unable to set debconf for slapd.")

    def tls_gen(self, org=None) -> None:
        """Create CA cert.

        Parameters
        ----------
        org : str
            Organization name.
        """
        if org:
            # Create Private Key for Certificate Authority(CA)
            pkc_args = [
                "certtool",
                "--generate-privkey",
                "--bits",
                "4096",
                "--outfile",
                "/etc/ssl/private/mycakey.pem",
            ]
            rc = subprocess.call(pkc_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to create private key.")

            # CA Template
            ca_template = [f"cn = {org}", "ca", "cert_signing_key", "expiration_days = 3650"]
            with open("/etc/ssl/ca.info", "w") as f:
                for line in ca_template:
                    f.write(f"{line}\n")

            # Create CA Certificate
            ca_cert_args = [
                "certtool",
                "--generate-self-signed",
                "--load-privkey",
                "/etc/ssl/private/mycakey.pem",
                "--template",
                "/etc/ssl/ca.info",
                "--outfile",
                "/usr/local/share/ca-certificates/mycacert.crt",
            ]

            rc = subprocess.call(ca_cert_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to create certificate authority.")

            # Add CA certificate to trusted certs
            rc = subprocess.call(
                ["update-ca-certificates"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
            )

            if rc != 0:
                raise Exception("Unable to add CA certificate to trusted certs")

            # Get Server Hostname
            result = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True)

            # Private Key for Server
            pks_args = [
                "certtool",
                "--generate-privkey",
                "--bits",
                "2048",
                "--outfile",
                "/etc/ldap/ldap01_slapd_key.pem",
            ]
            rc = subprocess.call(pks_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to create private key for server.")

            # Template for Server Certificate
            sc_template = [
                f"organization = {org}",
                f"cn = {result.stdout}",
                "tls_www_server",
                "encryption_key",
                "signing_key",
                "expiration_days = 365",
            ]
            with open("/etc/ssl/ldap01.info", "w") as f:
                for line in sc_template:
                    f.write(f"{line}\n")

            # Create Server Certificate
            sc_args = [
                "certtool",
                "--generate-certificate",
                "--load-privkey",
                "/etc/ldap/ldap01_slapd_key.pem",
                "--load-ca-certificate",
                "/etc/ssl/certs/mycacert.pem",
                "--load-ca-privkey",
                "/etc/ssl/private/mycakey.pem",
                "--template",
                "/etc/ssl/ldap01.info",
                "--outfile",
                "/etc/ldap/ldap01_slapd_cert.pem",
            ]
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
            sc_ldif = [
                "dn: cn=config",
                "add: olcTLSCACertificateFile",
                "olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem",
                "-",
                "add: olcTLSCertificateFile",
                "olcTLSCertificateFile: /etc/ldap/ldap01_slapd_cert.pem",
                "-",
                "add: olcTLSCertificateKeyFile",
                "olcTLSCertificateKeyFile: /etc/ldap/ldap01_slapd_key.pem",
            ]
            with open("/etc/ldap/certinfo.ldif", "w") as f:
                for line in sc_ldif:
                    f.write(f"{line}\n")

            # Apply Certificate LDIF
            ldif_args = [
                "ldapmodify",
                "-Y",
                "EXTERNAL",
                "-H",
                "ldapi:///",
                "-f",
                "/etc/ldap/certinfo.ldif",
            ]
            rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to apply Server Certificate LDIF")
        else:
            raise Exception("Organization not set.")

    def tls_load(self, domain=None):
        """Load and return CA cert and ldap uri.

        Parameters
        ----------
        domain : str
            Domain name.
        """
        if domain:
            dcs = self._split_domain(domain)

            # sssd conf template for clients
            ldap_uri = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True)
            sssd_conf = [
                "[sssd]",
                "config_file_version = 2",
                f"domains = {domain}",
                "",
                f"[domain/{domain}]",
                "id_provider = ldap",
                "auth_provider = ldap",
                f"ldap_uri = ldap://{ldap_uri.stdout}",
                "cache_credentials = True",
                f"ldap_search_base = {dcs}",
            ]
            with open("/etc/sssd/sssd_conf.template", "w") as f:
                for line in sssd_conf:
                    f.write(f"{line}\n")

            fd = FileData()
            fd.load("/etc/sssd/sssd_conf.template")
            sssd_conf = fd._dumps()
            fd.load("/usr/local/share/ca-certificates/mycacert.crt")
            ca_cert = fd._dumps()

            return ca_cert, sssd_conf
        else:
            raise Exception("Domain has not been set. Run action set-config first.")
