# OpenLDAP Charms

This repo provides two charms:
* [server](server/README.md) (LDAP Server)
* [client](client/README.md) (LDAP Client)

## To Build

Prerequisites:
* snap
* charmcraft (snap package)
* juju (snap package)

Clone this repository:

```
git clone <repo-url>
```

Build:

```
cd server
charmcraft -v pack
cd client
charmcraft -v pack
```

Deploy:

```
juju deploy ./openldap-server_ubuntu-22.04-amd64.charm  --series=jammy
juju deploy ./openldap-client_ubuntu-22.04-amd64.charm -n <#-of-client-units> --series=jammy
```

Actions:

```
# Set configuration
juju run-action openldap-server/0 configure admin-passwd="test" domain="example.com" org="HPC" --wait

# Relate server and client
juju relate openldap-server:ldap-auth openldap-client:ldap-auth

# Add Group
juju run-action openldap-server/0 add-group admin-passwd="test" gid=1005 group="bob" --wait

# Add User
juju run-action openldap-server/0 add-user admin-passwd="test" gecos="bob" gid=1005 homedir="/home/bob" shell="/bin/bash" uid=1005 passwd="abc" user="bob" --wait
```