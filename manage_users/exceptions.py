class DuplicateUserError(Exception):
    """
        Raised when an attempt is made to create a user which already exists.
    """

    def __init__(self, user):
        """
            Create the duplicate user exception.

            Keyword arguments:
            user -- The name of the user that the collision occurred for.
        """
        super(DuplicateUserError, self).__init__(
            'Cannot create {user}, as this user already exists.'.format(
                user=user
            ),
        )

class NoSuchUserError(Exception):
    """
        Raised when an attempt is made to operate on a nonexistent user.
    """

    def __init__(self, user):
        """
            Create the missing user exception.

            Keyword arguments:
            user -- The name of the user that could not be found.
        """
        super(NoSuchUserError, self).__init__(
            'Could not modify {user} as they do not exist.'.format(
                user=user
            ),
        )

class SSHKeyNotFoundError(Exception):
    """
        Raised when an attempt is made to act on an SSH key for a user where
        the user does not have that many keys, or the user does not exist.
    """

    def __init__(self, user, key_id):
        """
            Create missing SSH key exception.

            Keyword arguments:
            user -- The name of the user that the key could not be found for.
            key_id -- The ID of the key that could not be found.
        """
        message =  'Could not find {key_id} for {user}.'.format(
            user=user,
            key_id=key_id,
        )
        message += (' Either the user does not have this many keys, or'
                    ' they do not exist.')

        super(SSHKeyNotFoundError, self).__init__(message)
