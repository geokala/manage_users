#! /usr/bin/env python3
from distutils.core import setup
import os

setup(
    name='manage_users',
    version='2.0.1',
    description='Utility for managing users via configuration management'
                ' systems. Currently supports ansible only.',
    author='geokala',
    url='https://github.com/geokala',
    packages=['manage_users'],
    scripts=[os.path.join('scripts', script)
             for script in os.listdir('scripts/')],
    install_requires=['pyyaml'],
)
