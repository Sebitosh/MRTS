#!/usr/bin/env python3

import os
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
server_root_dir = os.path.join(current_dir, 'infra')
apache_conf_path = os.path.join(server_root_dir, 'apache2.conf')

stopcommand = [
    'apachectl',
    '-d', server_root_dir,  # Same server root directory
    '-f', apache_conf_path,  # Same config file
    '-k', 'stop'  # Stop the server
]


subprocess.run(stopcommand, check=True)
