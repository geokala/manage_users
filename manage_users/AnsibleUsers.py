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
        self.playbook = [{'hosts': hosts, 'tasks': []}]

    def get_users(self, include_active=True, include_inactive=True):
        """
            Return a dict indexed on the users in the playbook, with details
            of those users as the associated values.

            Keyword arguments:
            include_active -- Include active users (default: True)
            include_inactive -- Include inactive users (default: True)
        """
        playbook_tasks = self.playbook[0]['tasks']

        # Get all users
        users = defaultdict(dict)
        for task in playbook_tasks:
            if 'user' in task.keys():
                user = task['user']

                # Only add if we're not filtering
                user_active = self.state_mapping[user['state']]
                if user_active and include_active or \
                   (not user_active) and include_inactive:

                    users[user['name']].update(user)
                    users[user['name']]['enabled'] = self.state_mapping[
                        users[user['name']]['state']
                    ]
            elif 'authorized_key' in task.keys():
                key_details = task['authorized_key']

                # Don't add the key if the user was filtered
                if key_details['user'] not in users:
                    continue

                if 'sshkeys' not in users[key_details['user']].keys():
                    users[user['name']]['sshkeys'] = []
                users[user['name']]['sshkeys'].append({
                    'key': key_details['key'],
                    'enabled': self.state_mapping[key_details['state']],
                })

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

        group = {
            'name': user,
            'gid': self.next_id,
            'state': 'present',
        }

        user_settings = {
            'name': user,
            'password': self._hash_password(password),
            'group': user,
            'uid': self.next_id,
            'shell': '/bin/bash',
            'state': 'present',
            'groups': 'sudo',
        }

        if comment is not None:
            user_settings['comment'] = comment

        self.playbook[0]['tasks'].append({
            'name': 'Manage group for {user}'.format(user=user),
            'group': group,
        })
        self.playbook[0]['tasks'].append({
            'name': 'Manage user for {user}'.format(user=user),
            'user': user_settings,
        })

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

        authorized_key = {
            'user': user,
            'key': key,
            'state': 'present',
        }

        # Differentiate key management task names based on the number of keys
        # registered to this user
        key_count = len(users[user].get('sshkeys', [])) + 1

        self.playbook[0]['tasks'].append({
            'name': 'Manage sshkey {count} for user {user}'.format(
                user=user,
                count=key_count,
            ),
            'authorized_key': authorized_key,
        })

    def _modify_user_attribute(self, user, attribute, new_value):
        """
            Change a single attribute for a user.

            Keyword arguments:
            user -- The name of the user to change an attribute for.
            attribute -- The name of the attribute to change.
            new_value -- The new value of the attribute.
        """
        for task in self.playbook[0]['tasks']:
            if 'user' in task.keys() and task['user']['name'] == user:
                task['user'][attribute] = new_value
                # We've found the user, we can stop now
                break
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
        self._modify_user_attribute(
            user=user,
            attribute='state',
            new_value='present',
        )

    def disable_user(self, user):
        """
            Disable a user. This will render them unable to log in. Their
            details will not be removed from this list, and their UID will not
            be reused.

            Keyword arguments:
            user -- The user to disable.
        """
        self._modify_user_attribute(
            user=user,
            attribute='state',
            new_value='absent',
        )

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
        for task in self.playbook[0]['tasks']:
            if 'authorized_key' in task.keys() and \
               task['authorized_key']['name'] == user:
                # We found a key for this user- check it's the right one
                # The task name must be in the form:
                # 'Manage sshkey {count} for user {user}'
                this_id = int(task['name'][14:].split()[0])
                if this_id == target_key_id:
                    task['authorized_key'][attribute] = new_value
                    # We've found the key, we can stop now
                    break
        raise SSHKeyNotFoundError(user, target_key_id)

    def enable_sshkey(self, user, key_id):
        """
            Enables a disabled SSH key for a user. This will allow logins for
            that key again.

            Keyword arguments:
            user -- The name of the user whose SSH key should be affected.
            key_id -- The ID of the key to be affected.
        """
        self._modify_sshkey_attribute(
            user=user,
            target_key_id=key_id,
            attribute='state',
            new_value='present',
        )

    def disable_sshkey(self, user, key_id):
        """
            Disables an SSH key for a user, preventing that key from being
            used to log in.

            Keyword arguments:
            user -- The name of the user whose SSH key should be affected.
            key_id -- The ID of the key to be affected.
        """
        self._modify_sshkey_attribute(
            user=user,
            target_key_id=key_id,
            attribute='state',
            new_value='absent',
        )
