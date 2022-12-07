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

DOMAIN = "lxd"
MIN_GID = 999
MIN_UID = 999

class LdapServer:
    """Server to provide LDAP server charm all functionality needed."""

    packages = ["slapd", "ldap-utils", "sssd-ldap", "gnutls-bin", "ssl-cert"]
    systemd_services = ["slapd"]    

    def __init__(self):
        pass

    def _add_base(self, passwd):
        """Define base for groups and users."""

        base = [f"dn: ou=People,dc={DOMAIN}", "objectClass: organizationalUnit", 
                "ou: People", "", f"dn: ou=Groups,dc={DOMAIN}", 
                "objectClass: organizationalUnit", "ou: Groups"]
        
        with open("/etc/ldap/basedn.ldif", "w") as f:
            for l in base:
                f.write(f"{l}\n")

        binddn = f"cn=admin,dc={DOMAIN}"
        cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", "/etc/ldap/basedn.ldif"]
        
        rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if rc != 0:
            raise Exception("Unable to add basedn ldif.")

    def add_user(self, gid=None, passwd=None, uid=None, upasswd=None, user=None):
        """Add user."""

        if user and passwd and upasswd and uid and uid > MIN_UID and gid and gid > MIN_GID:
            binddn = f"cn=admin,dc={DOMAIN}"
            base_user = [f"dn: uid={user.lower()},ou=people,dc={DOMAIN}", "objectClass: inetOrgPerson",
                          "objectClass: posixAccount", "objectClass: shadowAccount",
                          f"cn: {user.lower()}", f"sn: {user}", f"userPassword: {upasswd}",
                          "loginShell: /bin/bash", f"uidNumber: {uid}", f"gidNumber: {gid}",
                          f"homeDirectory: /home/{user.lower()}"]
            
            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                for l in base_user:
                    f.write(f"{l}\n")
                    f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception("Unable to add user. Make sure to run \"ldapadd -x -D cn=admin,dc=lxd -W -f /etc/ldap/basedn.ldif\" first.")
    
    def add_group(self, gid=None, group=None, passwd=None):
        """Add group."""

        if group and passwd and gid and gid > MIN_GID:
            binddn = f"cn=admin,dc={DOMAIN}"
            base_group = [f"dn: cn={group},ou=Groups,dc={DOMAIN}", "objectClass: posixGroup",
                          f"cn: {group}", f"gidNumber: {gid}"]

            with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
                for l in base_group:
                    f.write(f"{l}\n")
                    f.flush()
                cmd = ["ldapadd", "-x", "-D", binddn, "-w", passwd, "-f", f.name]

                rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                if rc != 0:
                    raise Exception("Unable to add group. Make sure to run \"ldapadd -x -D cn=admin,dc=lxd -W -f /etc/ldap/basedn.ldif\" first.")

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

    def set_config(self, passwd=None):
        """Set LDAP password and slapd configuration."""

        if passwd:
            # Reconfigure slapd with password
            self.tls_deb(passwd)
            self._add_base(passwd)

            # Apply Certificate LDIF
            ldif_args = ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/etc/ldap/certinfo.ldif"]
         
            rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

            if rc != 0:
                raise Exception("Unable to apply Server Certificate LDIF")

    def start(self):
        """Start services."""

        for name in self.systemd_services:
            systemd.service_start(name)

    def stop(self):
        """Stop services."""

        for name in self.systemd_services:
            systemd.service_stop(name)

    def tls_deb(self, passwd):
        """Configuration of slapd noninteractive."""

        # rc = subprocess.call(["export", "DEBIAN_FRONTEND=noninteractive"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, shell=True)
        # if rc != 0:
        #        raise Exception(f"Unable to export.")

        args = [
            "slapd slapd/no_configuration boolean false", "slapd slapd/domain string lxd",
            "slapd shared/organization string lxd", f"slapd slapd/password1 password {passwd}",
            f"slapd slapd/password2 password {passwd}", "slapd slapd/purge_database boolean true",
            "slapd slapd/move_old_database boolean true"
        ]

        with tempfile.NamedTemporaryFile(mode="w+t", delete=True) as f:
            for arg in args:
                f.write(f"{arg}\n")
                f.flush()
            
            ps = subprocess.Popen(('cat', f'{f.name}'), stdout=subprocess.PIPE)
            output = subprocess.check_output(('debconf-set-selections'), stdin=ps.stdout)
            ps.wait()

        rc = subprocess.call(["dpkg-reconfigure", "-f", "noninteractive", "slapd"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if rc != 0:
            raise Exception(f"Unable to set debconf for slapd.")
    
    def tls_gen(self):
        """Create CA cert."""

        # Write base ldif
        # self._add_base()

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
        ldif_args = ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/etc/ldap/certinfo.ldif"]
        # TODO: Won't work till `dpkg-reconfigure slapd` is done
        rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        if rc != 0:
            raise Exception("Unable to apply Server Certificate LDIF")

    def tls_load(self):
        """Load and return CA cert and ldap uri."""
        
        # Apply Certificate LDIF
        # ldif_args = ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/etc/ldap/certinfo.ldif"]
        # Won't work till `dpkg-reconfigure slapd` is done
        # rc = subprocess.call(ldif_args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

        # if rc != 0:
        #    raise Exception("Unable to apply Server Certificate LDIF. Run `sudo dpkg-reconfigure slapd` first.")

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
