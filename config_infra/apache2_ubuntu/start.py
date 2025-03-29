#!/usr/bin/env python3

import os
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
server_root_dir = os.path.join(current_dir, 'infra')
apache_conf_path = os.path.join(server_root_dir, 'apache2.conf')

startcommand = [
    'apachectl',
    '-d', server_root_dir,  # Use the absolute path of the current directory
    '-f', apache_conf_path  # Path to apache2.conf
]

subprocess.run(startcommand, check=True)
