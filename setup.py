#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

#with open('requirements.txt') as f:
#    required = f.read().splitlines()

setup(name='xmldsig',
      version='0.2.1',
      author='Ralph Broenink',
      author_email='jrbroenink@antagonist.nl',
      license='BSD',
      description='Convenience wrapper for the PyXMLSec library',
      py_modules=['xmldsig'],
      install_requires=['pyxmlsec-next', 'libxml2-python'],
      test_suite='tests')