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
        base = (
            f"dn: ou=People,{dcs}\n"
            "objectClass: organizationalUnit\n"
            "ou: People\n"
            "\n"
            f"dn: ou=Groups,{dcs}\n"
            "objectClass: organizationalUnit\n"
            "ou: Groups\n"
        )

        with open("/etc/ldap/basedn.ldif", "w") as f:
            f.write(base)

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
            raise Exception("gid must be below {MIN_GID}.")
        elif None in [domain, gid, group, admin_passwd]:
            raise Exception("add-group parameters can not be None.")
        else:
            binddn = f"cn=admin,{dcs}"
            base_group = (
                f"dn: cn={group},ou=Groups,{dcs}\n"
                "objectClass: posixGroup\n"
                f"cn: {group}\n"
                f"gidNumber: {gid}\n"
            )

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                f.write(base_group)
                f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", admin_passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add group. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

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
            raise Exception(f"uid and gid must be below {MIN_UID}.")
        elif None in [admin_passwd, dcs, gecos, gid, homedir, shell, passwd, uid, user]:
            raise Exception("add-user parameters can not be None.")
        else:
            binddn = f"cn=admin,{dcs}"
            base_user = (
                f"dn: uid={user.lower()},ou=people,{dcs}\n"
                "objectClass: inetOrgPerson\n"
                "objectClass: posixAccount\n"
                "objectClass: shadowAccount\n"
                f"cn: {user.lower()}\n"
                f"sn: {user}\n"
                f"userPassword: {passwd}\n"
                f"loginShell: {shell}\n"
                f"uidNumber: {uid}\n"
                f"gidNumber: {gid}\n"
                f"homeDirectory: {homedir}\n"
                f"gecos: {gecos}\n"
            )

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                f.write(base_user)
                f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", admin_passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception(
                        f'Unable to add user. Make sure to run "ldapadd -x -D cn=admin,{dcs} -W -f /etc/ldap/basedn.ldif" first.'
                    )

    def auth_load(self, domain=None):
        """Load and return CA cert and sssd configuration.

        Parameters
        ----------
        domain : str
            Domain name.
        """
        if domain is None:
            logger.error("Domain can not be None. Run action configure first.")
            return
        else:
            dcs = self._split_domain(domain)

            # sssd conf template for clients
            ldap_uri = subprocess.run(["cat", "/etc/hostname"], capture_output=True, text=True)
            sssd_conf = (
                "[sssd]\n"
                "config_file_version = 2\n"
                f"domains = {domain}\n"
                "\n"
                f"[domain/{domain}]\n"
                "id_provider = ldap\n"
                "auth_provider = ldap\n"
                f"ldap_uri = ldap://{ldap_uri.stdout.strip()}\n"
                "cache_credentials = True\n"
                f"ldap_search_base = {dcs}\n"
            )
            with open("/etc/sssd/sssd_conf.template", "w") as f:
                f.write(sssd_conf)

            fd = FileData()
            fd.load("/etc/sssd/sssd_conf.template")
            sssd_conf = fd._dumps()
            fd.load("/usr/local/share/ca-certificates/mycacert.crt")
            ca_cert = fd._dumps()

            return ca_cert, sssd_conf

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
        arg = (
            "slapd slapd/no_configuration boolean false\n"
            f"slapd slapd/domain string {domain}\n"
            f"slapd shared/organization string {org}\n"
            f"slapd slapd/password1 password {admin_passwd}\n"
            f"slapd slapd/password2 password {admin_passwd}\n"
            "slapd slapd/purge_database boolean true\n"
            "slapd slapd/move_old_database boolean true\n"
        )

        with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
            f.write(arg)
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
        if not org:
            raise Exception("Organization not set.")
        else:
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
            ca_template = (f"cn = {org}\n" "ca\n" "cert_signing_key\n" "expiration_days = 3650\n")
            with open("/etc/ssl/ca.info", "w") as f:
                f.write(ca_template)

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
            hostname = subprocess.run(
                ["cat", "/etc/hostname"], capture_output=True, text=True
            ).stdout.strip()

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
            sc_template = (
                f"organization = {org}\n"
                f"cn = {hostname}\n"
                "tls_www_server\n"
                "encryption_key\n"
                "signing_key\n"
                "expiration_days = 365\n"
            )
            with open(f"/etc/ssl/ldap-{hostname}.info", "w") as f:
                f.write(sc_template)

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
            sc_ldif = (
                "dn: cn=config\n"
                "add: olcTLSCACertificateFile\n"
                "olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem\n"
                "-\n"
                "add: olcTLSCertificateFile\n"
                f"olcTLSCertificateFile: /etc/ldap/ldap-{hostname}_slapd_cert.pem\n"
                "-\n"
                "add: olcTLSCertificateKeyFile\n"
                f"olcTLSCertificateKeyFile: /etc/ldap/ldap-{hostname}_slapd_key.pem\n"
            )
            with open("/etc/ldap/certinfo.ldif", "w") as f:
                f.write(sc_ldif)

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
