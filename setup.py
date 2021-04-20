#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

from setuptools import setup, find_packages

from penne import (
    __version__,
    __contact__,
    __author__,
    __website__,
    __license__
)

setup(
    name='penneav',
    version=__version__,
    packages=find_packages(),
    url=__website__,
    license=__license__,
    author=__author__,
    author_email=__contact__,
    description='Penne AV is a cross platform AV solution written in python for portability and ease',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    project_urls={
        "Bug Tracker": "https://github.com/Penetrum-Security/Penne/issues/new",
        "Documentation": "https://github.com/Penetrum-Security/Penne/wiki",
        "Source Code": "https://github.com/Penetrum-Security/Penne",
    },
    install_requires=open("requirements.txt").read().split("\n"),
    scripts=["penneav"]
)
