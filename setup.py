from setuptools import setup, find_packages

setup(
    name='penne',
    version='0.0.1',
    packages=find_packages(),
    url='https://penetrum.com',
    license='MIT',
    author='Penetrum LLC',
    author_email='contact@penetrum.com',
    description='Penne AV is a cross platform AV solution written in python for portability and ease',
    scripts=["penne/bin/penne"],
    project_urls={
        "Bug Tracker": "https://github.com/Penetrum-Security/Penne/issues/new",
        "Documentation": "https://github.com/Penetrum-Security/Penne/wiki",
        "Source Code": "https://github.com/Penetrum-Security/Penne",
    }
)
