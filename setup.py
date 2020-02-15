#!/usr/bin/env python
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pastehunter',
    version='1.3.1',
    author='@kevthehermit @Plazmaz',
    author_email='info@pastehunter.com',
    description="Pastehunter",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://pastehunter.com',
    license='GNU V3',
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'yara-python',
        'requests',
        'elasticsearch',
        'splunk-sdk'
    ],
    scripts=['pastehunter-cli'],
    package_data={'': ['*.yar', 'README.md, LICENSE']}
)