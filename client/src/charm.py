#!/usr/bin/env python3
# Copyright 2022 Canonical
# See LICENSE file for licensing details.
"""OPENLDAP CLIENT OPERATOR.

This operator provides an LDAP client that connects to the server with SSSD.

Utilizes a requires relation to connect to the server.

charmcraft -v pack
juju deploy ./hpct-openldap-client_ubuntu-22.04-amd64.charm -n <#-of-client-units>
"""

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

from managers.openldap import OpenldapClientManager

logger = logging.getLogger(__name__)


class OpenldapClientCharm(CharmBase):
    """HPC LDAP Client Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Integrations
        self.framework.observe(
            self.on.ldap_auth_relation_changed, self._on_ldap_auth_relation_changed
        )
        # Client Manager
        self.ldapclient_manager = OpenldapClientManager()

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        self.ldapclient_manager.install()
        if not self.ldapclient_manager.is_installed():
            logger.error("Install failed, required packages not found.")

    def _on_start(self, event):
        """Handle start event."""
        logger.info("Start")
        self.ldapclient_manager.start()
        self.unit.status = ActiveStatus("LDAP Client Started")

    def _on_ldap_auth_relation_changed(self, event):
        """Handle ldap-auth relation changed event."""
        auth_relation = self.model.get_relation("ldap-auth")
        ca_cert = auth_relation.data[event.app].get("ca-cert")
        sssd_conf = auth_relation.data[event.app].get("sssd-conf")
        if ca_cert and sssd_conf:
            self.ldapclient_manager.save_ca_cert(ca_cert)
            self.ldapclient_manager.save_sssd_conf(sssd_conf)
            logger.info("ldap-auth relation-changed data found.")
        else:
            logger.info("ldap-auth relation-changed data not found: ca-cert and sssd-conf.")

if __name__ == "__main__":  # pragma: nocover
    main(OpenldapClientCharm)
