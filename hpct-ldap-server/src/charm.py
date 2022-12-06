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
from ops.model import (
    ActiveStatus,
    WaitingStatus
)

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
        self.framework.observe(self.on.tls_transfer_action, self._on_tls_transfer_action)
        # Server Manager
        self.ldapserver_manager = LdapServer()

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        self.ldapserver_manager.install()

    def _on_start(self, event):
        """Handle start event."""
        self.ldapserver_manager.start()
        self.ldapserver_manager.tls_gen()
        self.unit.status = ActiveStatus("LDAP Server Started")

    def _on_tls_transfer_action(self, event):
        """Handle the tls-transfer action."""
       # Get TLS relation
        tls_relation = self.model.get_relation("tls-cert")
        if not tls_relation:
            self.unit.status = WaitingStatus("Waiting for ldap-tls relation to be created")
            event.defer()
            return
        ca_cert, sssd_conf = self.ldapserver_manager.tls_load()
        tls_relation.data[self.app].update(
            {
                "ca": ca_cert,
                "sssd": sssd_conf,
            }
        )

if __name__ == "__main__":  # pragma: nocover
    main(LdapServerCharm)
