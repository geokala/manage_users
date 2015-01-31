#! /usr/bin/env python3
from collections import defaultdict
import crypt
from manage_users.exceptions import (DuplicateUserError, NoSuchUserError,
                                     SSHKeyNotFoundError)
import yaml


class AnsibleUsers(object):
    """
        Manage users in an ansible playbook.

        This playbook should be one entirely managed by this class.
    """

    state_mapping = {
        'present': True,
        'absent': False,
    }
    playbook = None

    def __init__(self, playbook_path='test/example.yml', base_id=10000):
        """
            Initialise the ansible user management module.

            Keyword arguments:
            playbook_path -- Path to the playbook you wish to manage.
            base_id -- The base ID for users and groups. Any new IDs will be
                       at least this ID, or the highest currently in the file
                       + 1, if there are existing users.
        """
        self.playbook_path = playbook_path
        self.next_id = base_id

    def load_playbook(self):
        """
            Load the playbook this class is associated with.
        """
        with open(self.playbook_path) as playbook_handle:
            data = playbook_handle.read()
        self.playbook = yaml.load(data)

        # Update the base ID
        users = self.get_users(include_active=True, include_inactive=True)
        for user in users.values():
            if user['uid'] >= self.next_id:
                self.next_id = user['uid'] + 1

    def save_playbook(self):
        """
            Save the playbook this class is associated with.
        """
        with open(self.playbook_path, 'w') as playbook_handle:
            playbook_handle.write(yaml.dump(self.playbook))

    def create_base_playbook(self, hosts='all'):
        """
            Initialise the playbook with the base required data.

            This is intended to be used to bootstrap a system which does not
            already have a playbook managed by this application.

            Keyword arguments:
            hosts -- Which hosts/groups should be managed by this application.
                     This should be a comma separated string.
                     (default: all)
        """
        self.playbook = [{
            'hosts': hosts,
            'tasks': [
                {
                    'name': 'manage enabled user groups',
                    'group': 'name="{{item.username}}" '
                             'gid="{{item.uid}}" '
                             'state=present',
                    'with_items': 'enabled_users',
                },
                {
                    'name': 'manage enabled users',
                    'user': 'name="{{item.username}}" '
                            'group="{{item.username}}" '
                            'uid="{{item.uid}}" '
                            'state=present '
                            'groups=sudo '
                            'password="{{item.password}}" '
                            'shell=/bin/bash '
                            '{% if item.comment is defined %}'
                            '"comment={{item.comment}}"'
                            '{% endif %}',
                    'with_items': 'enabled_users',
                },
                {
                    'name': 'manage enabled ssh keys',
                    'authorized_key': 'key="{{item.1.type}} '
                                      '{{item.1.key}} '
                                      '{{item.1.id}}" '
                                      'user="{{item.0.username}}" '
                                      'state=present',
                    'with_subelements': [
                        'enabled_users',
                        'sshkey_enabled',
                    ],
                },
                {
                    'name': 'manage disabled ssh keys',
                    'authorized_key': 'key="{{item.1.type}} '
                                      '{{item.1.key}} '
                                      '{{item.1.id}}" '
                                      'user="{{item.0.username}}" '
                                      'state=absent',
                    'with_subelements': [
                        'enabled_users',
                        'sshkey_disabled',
                    ],
                },
                {
                    'name': 'manage disabled users',
                    'user': 'name="{{item.username}}" '
                            'uid="{{item.uid}}" '
                            'state=present',
                    'with_items': 'disabled_users',
                },
                {
                    'name': 'manage disabled user groups',
                    'group': 'name="{{item.username}}" '
                             'gid="{{item.uid}}" '
                             'state=absent',
                    'with_items': 'disabled_users',
                },
            ],
            'vars': [
                {
                    'enabled_users': [],
                },
                {
                    'disabled_users': [],
                },
            ],
        }]

    def _form_sshkey_dict(self, user):
        """
            Take a user object (containing sshkey_enabled and sshkey_disabled
            keys), and return a dict with the sshkeys keyed on ID.

            Keyword arguments:
            user -- A user from the ansible playbook.
        """
        keys = {}
        for state in ('enabled', 'disabled'):
            for sshkey in user['sshkey_{state}'.format(state=state)]:
                keys[sshkey['id']] = {
                    'type': sshkey['type'],
                    'key': sshkey['key'],
                    'id': sshkey['id'],
                    'enabled': True if state == 'enabled' else False,
                }
        return keys

    def _get_userlist(self, enabled=True):
        """
            Get the enabled or disabled user list.
        """
        if enabled:
            search_string = 'enabled_users'
        else:
            search_string = 'disabled_users'
        for var in self.playbook[0]['vars']:
            if search_string in var.keys():
                return var[search_string]

    def get_users(self, include_active=True, include_inactive=True):
        """
            Return a dict indexed on the users in the playbook, with details
            of those users as the associated values.

            Keyword arguments:
            include_active -- Include active users (default: True)
            include_inactive -- Include inactive users (default: True)
        """
        # TODO: Support changing of default shell and groups
        default_shell = '/bin/bash'
        default_groups = 'sudo'

        # Prepare the user list
        users = defaultdict(dict)

        if include_active:
            enabled_users = self._get_userlist(enabled=True)
            for user in enabled_users:
                users[user['username']] = {
                    'enabled': True,
                    'uid': user['uid'],
                    'password': user['password'],
                    'shell': default_shell,
                    'groups': default_groups,
                    'sshkeys': self._form_sshkey_dict(user),
                }

        if include_inactive:
            disabled_users = self._get_userlist(enabled=False)
            for user in disabled_users:
                users[user['username']] = {
                    'enabled': False,
                    'uid': user['uid'],
                    'password': user['password'],
                    'shell': default_shell,
                    'groups': default_groups,
                    'sshkeys': self._form_sshkey_dict(user),
                }

        return users

    def _hash_password(self, password):
        """
            Return the hashed form of the supplied password, in a format
            usable in standard /etc/passwd on Ubuntu systems.

            Note: SHA512 hashes only.

            Keyword arguments:
            password -- The password to hash.
        """
        type_and_salt = crypt.mksalt(crypt.METHOD_SHA512)
        passwd_hash = crypt.crypt(password, type_and_salt)
        return passwd_hash

    def create_user(self, user, password, comment=None, sshkeys=[]):
        """
            Add a new user to the playbook.

            Keyword arguments:
            user -- The name of the new user.
            password -- The password of the new user. This will be hashed
                        automatically as SHA512.
            comment -- A comment to be added to this user's passwd entries.
                       (default: None)
            sshkeys -- List of SSH keys to add to authorized_keys for this
                       user. (default: No keys (empty list))
        """
        if user in self.get_users().keys():
            raise DuplicateUserError(user)

        user_settings = {
            'username': user,
            'password': self._hash_password(password),
            'uid': self.next_id,
            'sshkey_enabled': [],
            'sshkey_disabled': [],
        }

        if comment is not None:
            user_settings['comment'] = comment

        self._get_userlist(enabled=True).append(
            user_settings
        )

        for key in sshkeys:
            self.add_sshkey(user, key)

    def add_sshkey(self, user, key):
        """
            Add an ssh key for a given user.

            Keyword arguments:
            user -- The name of the user to add the new key for.
            key -- The key to add.
        """
        users = self.get_users()
        if user not in users.keys():
            raise NoSuchUserError(user)

        # TODO: Sanity checking- make sure the key is valid

        key = key.split(maxsplit=2)
        if len(key) == 1:
            # TODO: Proper failure to be raised
            raise ValueError
        elif len(key) == 2:
            key_id = str(len(users[user].get('sshkeys', [])) + 1)
        else:
            key_id = key.pop()

        key_type = key[0]
        key = key[1]

        authorized_key = {
            'type': key_type,
            'key': key,
            'id': key_id,
        }

        users = self._get_userlist(enabled=True)

        for candidate_user in users:
            if candidate_user['username'] == user:
                candidate_user['sshkey_enabled'].append(authorized_key)
                return

    def _modify_user_attribute(self, user, attribute, new_value):
        """
            Change a single attribute for a user.

            Keyword arguments:
            user -- The name of the user to change an attribute for.
            attribute -- The name of the attribute to change.
            new_value -- The new value of the attribute.
        """
        users = self._get_userlist(enabled=True)
        users.extend(self._get_userlist(enabled=False))

        for candidate_user in users:
            if candidate_user['username'] == user:
                candidate_user[attribute] = new_value
                # We've found the user, we can stop now
                return
        # If we don't find the user, complain
        raise NoSuchUserError(user)

    def change_password(self, user, password):
        """
            Change the password for an existing user.

            Keyword arguments:
            user -- The name of the user you wish to change the password for.
            password -- The new password for this user. This will be hashed
                        automatically as SHA512.
        """
        self._modify_user_attribute(
            user=user,
            attribute='password',
            new_value=self._hash_password(password),
        )

    def enable_user(self, user):
        """
            Enable a previously disabled user. This will allow them to resume
            logging in.

            Keyword arguments:
            user -- The user to enable.
        """
        enabled_users = self._get_userlist(enabled=True)
        disabled_users = self._get_userlist(enabled=False)

        for candidate_user in disabled_users:
            if candidate_user['username'] == user:
                enabled_users.append(candidate_user)
                disabled_users.remove(candidate_user)
                return
        # If we don't find the user, complain
        raise NoSuchUserError(user)

    def disable_user(self, user):
        """
            Disable a user. This will render them unable to log in. Their
            details will not be removed from this list, and their UID will not
            be reused.

            Keyword arguments:
            user -- The user to disable.
        """
        enabled_users = self._get_userlist(enabled=True)
        disabled_users = self._get_userlist(enabled=False)

        for candidate_user in enabled_users:
            if candidate_user['username'] == user:
                disabled_users.append(candidate_user)
                enabled_users.remove(candidate_user)
                return
        # If we don't find the user, complain
        raise NoSuchUserError(user)

    def _modify_sshkey_attribute(self, user, target_key_id,
                                 attribute, new_value):
        """
            Change a single attribute for one of a user's SSH keys.

            Keyword arguments:
            user -- The name of the user whose SSH key should be affected.
            target_key_id -- The ID of the key to change for that user.
            attribute -- The name of the attribute to change.
            new_value -- The new value of the attribute.
        """
        users = self._get_userlist(enabled=True)
        users.extend(self._get_userlist(enabled=False))

        for candidate_user in users:
            if candidate_user['username'] == user:
                keys = candidate_user['sshkey_enabled']
                keys.extend(candidate_user['sshkey_disabled'])
                for key in keys:
                    if key['id'] == target_key_id:
                        key[attribute] = new_value
                        # We've found the key, we can stop now
                        return
        raise SSHKeyNotFoundError(user, target_key_id)

    def enable_sshkey(self, user, key_id):
        """
            Enables a disabled SSH key for a user. This will allow logins for
            that key again.

            Keyword arguments:
            user -- The name of the user whose SSH key should be affected.
            key_id -- The ID of the key to be affected.
        """
        users = self._get_userlist(enabled=True)
        users.extend(self._get_userlist(enabled=False))

        for candidate_user in users:
            if candidate_user['username'] == user:
                enabled_keys = candidate_user['sshkey_enabled']
                disabled_keys = candidate_user['sshkey_disabled']
                for key in disabled_keys:
                    if key['id'] == key_id:
                        enabled_keys.append(key)
                        disabled_keys.remove(key)
                        return
        raise SSHKeyNotFoundError(user, key_id)

    def disable_sshkey(self, user, key_id):
        """
            Disables an SSH key for a user, preventing that key from being
            used to log in.

            Keyword arguments:
            user -- The name of the user whose SSH key should be affected.
            key_id -- The ID of the key to be affected.
        """
        users = self._get_userlist(enabled=True)
        users.extend(self._get_userlist(enabled=False))

        for candidate_user in users:
            if candidate_user['username'] == user:
                enabled_keys = candidate_user['sshkey_enabled']
                disabled_keys = candidate_user['sshkey_disabled']
                for key in enabled_keys:
                    if key['id'] == key_id:
                        disabled_keys.append(key)
                        enabled_keys.remove(key)
                        return
        raise SSHKeyNotFoundError(user, key_id)
