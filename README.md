Basic user management for environments using configuration management tools.

Currently only targeting ansible.

Remaining for 1.0.0:
* License (likely BSD)
* Tests
* Finish manuse CLI argparsing -- convert it to git style (subcommands manuse-command), and use argparse in the subcommand. Current approach is slightly deranged.
* Pipification - include dependency: pyyaml
* PEP8 checks (especially \_\_init\_\_.py)
