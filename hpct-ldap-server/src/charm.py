#!/usr/bin/env python3
# Copyright 2022 Canonical
# See LICENSE file for licensing details.
"""HPCT LDAP SERVER OPERATOR.

This operator provides directory services for all HPC-related operations as a service.

Utilizes a peer relation for failover server units.
Utilizes a provides relation for clients to connect to the server.

charmcraft -v pack
juju deploy ./hpct-ldap-server-operator_ubuntu-22.04-amd64.charm -n <#-of-failover-units>

For more info see:
https://hpc4can.ddns.net/xwiki/bin/view/Users/dvgomez/HPC%20LDAP%20Server%20and%20Client%20Operators/#
"""

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

from servers.ldap import LdapServer

logger = logging.getLogger(__name__)


class LdapServerCharm(CharmBase):
    """HPC LDAP Server Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Actions
        self.framework.observe(self.on.add_group_action, self._on_add_group_action)
        self.framework.observe(self.on.add_user_action, self._on_add_user_action)
        self.framework.observe(self.on.set_config_action, self._on_set_config_action)
        # Integrations
        self.framework.observe(
            self.on.tls_cert_relation_changed, self._on_tls_cert_relation_changed
        )
        # Server Manager
        self.ldapserver_manager = LdapServer()

    def _on_add_group_action(self, event):
        """Handle add-group action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        self.ldapserver_manager.add_group(
            event.params["admin-passwd"],
            domain,
            event.params["gid"],
            event.params["group"],
        )

    def _on_add_user_action(self, event):
        """Handle add-user action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        self.ldapserver_manager.add_user(
            event.params["admin-passwd"],
            domain,
            event.params["gecos"],
            event.params["gid"],
            event.params["homedir"],
            event.params["login"],
            event.params["passwd"],
            event.params["uid"],
            event.params["user"],
        )

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        self.ldapserver_manager.install()

    def _on_set_config_action(self, event):
        """Handle set-config action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        self.ldapserver_manager.set_config(
            event.params["admin-passwd"],
            event.params["domain"],
            event.params["org"],
        )
        self.ldapserver_manager.tls_gen(event.params["org"])
        replicas = self.model.get_relation("replicas")
        replicas.data[self.app].update(
            {
                "domain": event.params["domain"],
                "org": event.params["org"],
            }
        )

    def _on_start(self, event):
        """Handle start event."""
        self.ldapserver_manager.start()
        self.unit.status = ActiveStatus("LDAP Server Started")

    def _on_tls_cert_relation_changed(self, event):
        """Handle the tls-transfer action."""
        # Get TLS relation
        tls_relation = self.model.get_relation("tls-cert")
        # Get Replicas relation
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        if not tls_relation:
            self.unit.status = WaitingStatus("Waiting for ldap-tls relation to be created")
            event.defer()
            return
        if not domain:
            logger.info(f"domain: {domain}")
            self.unit.status = WaitingStatus("Waiting for set-config action to be run")
            event.defer()
            return
        ca_cert, sssd_conf = self.ldapserver_manager.tls_load(domain)
        tls_relation.data[self.app].update(
            {
                "ca": ca_cert,
                "sssd": sssd_conf,
            }
        )


if __name__ == "__main__":  # pragma: nocover
    main(LdapServerCharm)
