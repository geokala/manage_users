from manage_users.AnsibleUsers import AnsibleUsers  # noqa
from manage_users import script_helpers  # noqa
from manage_users.exceptions import (  # noqa
    DuplicateUserError,
    NoSuchUserError,
    SSHKeyNotFoundError,
)

__author__ = 'geokala- https://github.com/geokala'
__version__ = '2.0.0'
"""
    This module is designed to facilitate management of users through a
    configuration management system when centralised account management (such
    as LDAP) is not implemented.

    It is intended to be used through the 'manuse' utility that is deployed
    with it.

    See LICENSE file on github for license details.
"""
