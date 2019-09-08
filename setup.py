#!/usr/bin/env python

import sys
import os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

here = os.path.abspath(os.path.dirname(__file__))

setup(
    name='lazyzip',
    version='0.0.1',
    description='',
    #long_description=README,
    author='Koert van der Veer',
    author_email='lazyzip@ondergetekende.nl',
    url='https://github.com/',
    py_modules=['lazyzip'],
    #scripts=['my_module_name.py'],
    license='Apache2',
    install_requires=[],
)
