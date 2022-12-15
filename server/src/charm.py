#!/usr/bin/env python3
# Copyright 2022 Canonical
# See LICENSE file for licensing details.

import logging

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus

from managers.openldap import OpenldapServerManager

logger = logging.getLogger(__name__)


class OpenldapServerCharm(CharmBase):
    """HPC LDAP Server Charm."""

    def __init__(self, *args):
        super().__init__(*args)
        # Standard Charm Events
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        # Actions
        self.framework.observe(self.on.add_group_action, self._on_add_group_action)
        self.framework.observe(self.on.add_user_action, self._on_add_user_action)
        self.framework.observe(self.on.configure_action, self._on_configure_action)
        # Integrations
        self.framework.observe(
            self.on.ldap_auth_relation_changed, self._on_ldap_auth_relation_changed
        )
        # Server Manager
        self.ldapserver_manager = OpenldapServerManager()

    def _on_add_group_action(self, event):
        """Handle add-group action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        if not domain:
            event.fail("Domain has not been set.")
            return
        try:
            self.ldapserver_manager.add_group(
                event.params["admin-passwd"],
                domain,
                event.params["gid"],
                event.params["group"],
            )
        except Exception as e:
            event.fail(f"Failed to add group: {e}")
            return
        event.set_results({"result": "group added"})

    def _on_add_user_action(self, event):
        """Handle add-user action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        try:
            self.ldapserver_manager.add_user(
                event.params["admin-passwd"],
                domain,
                event.params["gecos"],
                event.params["gid"],
                event.params["homedir"],
                event.params["shell"],
                event.params["passwd"],
                event.params["uid"],
                event.params["user"],
            )
        except Exception as e:
            event.fail(f"Failed to add user: {e}")
            return
        event.set_results({"result": "user added"})

    def _on_install(self, event):
        """Handle install event."""
        logger.info("Install")
        if not self.ldapserver_manager.is_installed():
            self.ldapserver_manager.install()

    def _on_configure_action(self, event):
        """Handle set-config action."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return
        try:
            self.ldapserver_manager.configure(
                event.params["admin-passwd"],
                event.params["domain"],
                event.params["org"],
            )
        except Exception as e:
            event.fail(f"Failed to set LDAP configuration: {e}")
            return
        self.ldapserver_manager.tls_gen(event.params["org"])
        replicas = self.model.get_relation("replicas")
        replicas.data[self.app].update(
            {
                "domain": event.params["domain"],
                "org": event.params["org"],
            }
        )
        event.set_results({"result": "ldap configuration set"})

    def _on_start(self, event):
        """Handle start event."""
        self.ldapserver_manager.start()
        self.unit.status = ActiveStatus("LDAP Server Started")

    def _on_ldap_auth_relation_changed(self, event):
        """Handle the ldap-auth action."""
        # Get ldap-auth relation
        auth_relation = self.model.get_relation("ldap-auth")
        # Get Replicas relation
        replicas = self.model.get_relation("replicas")
        domain = replicas.data[self.app].get("domain")
        if not domain:
            event.fail("domain not set. run set-config action.")
            self.unit.status = WaitingStatus("Waiting for set-config action to be run")
            return
        ca_cert, sssd_conf = self.ldapserver_manager.auth_load(domain)
        auth_relation.data[self.app].update(
            {
                "ca-cert": ca_cert,
                "sssd-conf": sssd_conf,
            }
        )


if __name__ == "__main__":  # pragma: nocover
    main(OpenldapServerCharm)
