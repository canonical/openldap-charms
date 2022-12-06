#!/usr/bin/env python3
# Copyright 2022 Canonical
# See LICENSE file for licensing details.
"""HPCT LDAP CLIENT OPERATOR.

This operator provides an LDAP client that connects to the server with SSSD.

Utilizes a requires relation to connect to the server.

charmcraft -v pack
juju deploy ./hpct-ldap-client-operator_ubuntu-20.04-amd64.charm -n <#-of-client-units>
"""

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import (
    ActiveStatus,
    WaitingStatus
)

from servers.ldap import LdapClient

logger = logging.getLogger(__name__)


class LdapClientCharm(CharmBase):
    """HPC LDAP Client Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Relations
        self.framework.observe(self.on.tls_cert_relation_changed, self._on_tls_cert_relation_changed)
        # Server Manager
        self.ldapclient_manager = LdapClient()

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        self.ldapclient_manager.install()

    def _on_start(self, event):
        """Handle start event."""
        logger.info("Start")
        self.ldapclient_manager.start()
        self.unit.status = ActiveStatus("LDAP Client Started")

    def _on_tls_cert_relation_changed(self, event):
        """Handle ldap-tls relation changed event."""
        tls_relation = self.model.get_relation("tls-cert")
        if not tls_relation:
            self.unit.status = WaitingStatus("Waiting for ldap-tls relation to be created")
            event.defer()
            return
        ca_cert = tls_relation.data[event.app].get("ca")
        sssd_conf = tls_relation.data[event.app].get("sssd")
        if ca_cert and sssd_conf:
            self.ldapclient_manager.tls_save(ca_cert, sssd_conf)


if __name__ == "__main__":  # pragma: nocover
    main(LdapClientCharm)
