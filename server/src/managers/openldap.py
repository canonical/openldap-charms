# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# managers/ldap.py
"""Manager for server operator."""
import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from utils.filedata import FileData

MIN_GID = 999
MIN_UID = 999


class OpenldapServerManager:
    """Manager to provide LDAP server charm all functionality needed."""

    packages = ["slapd", "ldap-utils", "sssd-ldap", "gnutls-bin", "ssl-cert"]
    systemd_services = ["slapd"]

    def __init__(self):
        pass

    def _add_base(self, admin_passwd, dcs) -> None:
        """Define base for groups and users.

        Parameters
        ----------
        admin_passwd : str
            LDAP password.
        dcs : str
            Domain components.
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
        base = "\n".join(base)

        with open("/etc/ldap/basedn.ldif", "w") as f:
            f.write(f"{base}")

        binddn = f"cn=admin,{dcs}"
        cmd = ["ldapadd", "-x", "-D", binddn, "-w", admin_passwd, "-f", "/etc/ldap/basedn.ldif"]

        rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if rc != 0:
            raise Exception("Unable to add basedn ldif.")

    def _split_domain(self, dc) -> str:
        """Split domain components.

        Parameters
        ----------
        dc : str
            Domain components.
        """
        return ",".join([f"dc={x}" for x in dc.split(".")])

    def add_user(
        self,
        admin_passwd=None,
        domain=None,
        gecos=None,
        gid=None,
        homedir=None,
        shell=None,
        passwd=None,
        uid=None,
        user=None,
    ) -> None:
        """Add user.

        Parameters
        ----------
        admin_passwd : str
            LDAP password.
        domain : str
            Domain name.
        gecos : str
            Real name.
        gid : int
            Group id.
        homedir : str
            Home directory path.
        shell : str
            Login shell.
        passwd : str
            User password.
        uid : int
            User id.
        user : str
            Username.
        """
        dcs = self._split_domain(domain)
        if uid < MIN_UID or gid < MIN_GID:
            logger.error("uid and gid must be below {MIN_UID}.")
            return
        if (
            None not in [admin_passwd, dcs, gecos, gid, homedir, shell, passwd, uid, user]
        ):
            binddn = f"cn=admin,{dcs}"
            base_user = [
                f"dn: uid={user.lower()},ou=people,{dcs}",
                "objectClass: inetOrgPerson",
                "objectClass: posixAccount",
                "objectClass: shadowAccount",
                f"cn: {user.lower()}",
                f"sn: {user}",
                f"userPassword: {passwd}",
                f"loginShell: {shell}",
                f"uidNumber: {uid}",
                f"gidNumber: {gid}",
                f"homeDirectory: {homedir}",
                f"gecos: {gecos}",
            ]
            base_user = "\n".join(base_user)

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                f.write(f"{base_user}")
                f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", admin_passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add user. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

    def add_group(
        self,
        admin_passwd=None,
        domain=None,
        gid=None,
        group=None,
    ) -> None:
        """Add group.

        Parameters
        ----------
        admin_passwd : str
            LDAP password.
        domain : str
            Domain name.
        gid : int
            Group id.
        group : str
            Group name.
        """
        dcs = self._split_domain(domain)

        if gid < MIN_GID:
            logger.error("gid must be below {MIN_GID}.")
            return
        if None not in [domain, gid, group, admin_passwd]:
            binddn = f"cn=admin,{dcs}"
            base_group = [
                f"dn: cn={group},ou=Groups,{dcs}",
                "objectClass: posixGroup",
                f"cn: {group}",
                f"gidNumber: {gid}",
            ]
            base_group = "\n".join(base_group)

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                f.write(f"{base_group}")
                f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", admin_passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add group. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

    def auth_load(self, domain=None):
        """Load and return CA cert and sssd configuration.

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
            sssd_conf = "\n".join(sssd_conf)
            with open("/etc/sssd/sssd_conf.template", "w") as f:
                f.write(f"{sssd_conf}")

            fd = FileData()
            fd.load("/etc/sssd/sssd_conf.template")
            sssd_conf = fd._dumps()
            fd.load("/usr/local/share/ca-certificates/mycacert.crt")
            ca_cert = fd._dumps()

            return ca_cert, sssd_conf
        else:
            raise Exception("Domain has not been set. Run action set-config first.")

    def configure(self, admin_passwd=None, domain=None, org=None) -> None:
        """Set LDAP password and slapd configuration.

        Parameters
        ----------
        admin_passwd : str
            LDAP password.
        domain : str
            Domain name.
        org : str
            Organization name.
        """
        if domain and org and admin_passwd:
            dcs = self._split_domain(domain)

            # Reconfigure slapd with password
            self.slapd_config(admin_passwd, domain, org)
            self._add_base(admin_passwd, dcs)
        else:
            raise Exception("Domain, Organization, or Password is missing cannot complete action.")

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
                if not apt.DebianPackage.from_installed_package(name).present:
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

    def slapd_config(self, admin_passwd, domain, org) -> None:
        """Configuration of slapd noninteractive.

        Parameters
        ----------
        admin_passwd : str
            LDAP password.
        domain : str
            Domain name.
        org : str
            Organization name.
        """
        args = [
            "slapd slapd/no_configuration boolean false",
            f"slapd slapd/domain string {domain}",
            f"slapd shared/organization string {org}",
            f"slapd slapd/password1 password {admin_passwd}",
            f"slapd slapd/password2 password {admin_passwd}",
            "slapd slapd/purge_database boolean true",
            "slapd slapd/move_old_database boolean true",
        ]
        args = "\n".join(args)

        with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
            f.write(f"{args}")
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

    def start(self) -> None:
        """Start services."""
        for name in self.systemd_services:
            systemd.service_start(name)

    def stop(self) -> None:
        """Stop services."""
        for name in self.systemd_services:
            systemd.service_stop(name)

    

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
            ca_template = "\n".join(ca_template)
            with open("/etc/ssl/ca.info", "w") as f:
                f.write(f"{ca_template}")

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
            hostname = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True).stdout.strip()

            # Private Key for Server
            pks_args = [
                "certtool",
                "--generate-privkey",
                "--bits",
                "2048",
                "--outfile",
                f"/etc/ldap/ldap-{hostname}_slapd_key.pem",
            ]
            rc = subprocess.call(pks_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to create private key for server.")

            # Template for Server Certificate
            sc_template = [
                f"organization = {org}",
                f"cn = {hostname}",
                "tls_www_server",
                "encryption_key",
                "signing_key",
                "expiration_days = 365",
            ]
            sc_template = "\n".join(sc_template)
            with open(f"/etc/ssl/ldap-{hostname}.info", "w") as f:
                f.write(f"{sc_template}")

            # Create Server Certificate
            sc_args = [
                "certtool",
                "--generate-certificate",
                "--load-privkey",
                f"/etc/ldap/ldap-{hostname}_slapd_key.pem",
                "--load-ca-certificate",
                "/etc/ssl/certs/mycacert.pem",
                "--load-ca-privkey",
                "/etc/ssl/private/mycakey.pem",
                "--template",
                f"/etc/ssl/ldap-{hostname}.info",
                "--outfile",
                f"/etc/ldap/ldap-{hostname}_slapd_cert.pem",
            ]
            rc = subprocess.call(sc_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to create server certificate.")

            # Adjust Permissions and Ownership
            shutil.chown(f"/etc/ldap/ldap-{hostname}_slapd_key.pem", group="openldap")
            os.chmod(f"/etc/ldap/ldap-{hostname}_slapd_key.pem", 0o640)

            # Server Certificates LDIF
            sc_ldif = [
                "dn: cn=config",
                "add: olcTLSCACertificateFile",
                "olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem",
                "-",
                "add: olcTLSCertificateFile",
                f"olcTLSCertificateFile: /etc/ldap/ldap-{hostname}_slapd_cert.pem",
                "-",
                "add: olcTLSCertificateKeyFile",
                f"olcTLSCertificateKeyFile: /etc/ldap/ldap-{hostname}_slapd_key.pem",
            ]
            sc_ldif = "\n".join(sc_ldif)
            with open("/etc/ldap/certinfo.ldif", "w") as f:
                f.write(f"{sc_ldif}")

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
