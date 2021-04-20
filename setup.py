#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

from setuptools import setup, find_packages

setup(
    name='penne',
    version='0.1',
    packages=find_packages(),
    url='https://penetrum.com',
    license='MIT',
    author='Penetrum LLC',
    author_email='contact@penetrum.com',
    description='Penne AV is a cross platform AV solution written in python for portability and ease',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    project_urls={
        "Bug Tracker": "https://github.com/Penetrum-Security/Penne/issues/new",
        "Documentation": "https://github.com/Penetrum-Security/Penne/wiki",
        "Source Code": "https://github.com/Penetrum-Security/Penne",
    },
    install_requires=open("requirements.txt").read().split("\n"),
    scripts=["penne/bin/penne"]
)
