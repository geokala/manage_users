from manage_users import AnsibleUsers
import sys


def playbook_load_or_prompt_for_create(playbook_path, base_id):
    """
        Try to load the playbook, or prompt to see if the user wants it to be
        created if it doesn't exist.

        Keyword arguments:
        playbook_path -- Path to the ansible playbook
        base_id -- Base UID for users managed by this application
    """
    user_manager = AnsibleUsers(playbook_path=playbook_path,
                                base_id=base_id)
    try:
        user_manager.load_playbook()
    except FileNotFoundError:
        answer = ''
        while answer.lower() not in ('y', 'n'):
            answer = input(
                'Playbook not found in {path}.'
                ' Do you wish to create it (y/n)?'.format(
                    path=playbook_path
                )
            ).lower()
            if answer == 'y':
                user_manager.create_base_playbook()
                print('Playbook created in {path}'.format(path=playbook_path))
            elif answer == 'n':
                sys.stderr.write('I cannot continue without a playbook.\n')
                sys.exit(1)
            else:
                print('Please enter y for yes or n for no.')

    return user_manager
