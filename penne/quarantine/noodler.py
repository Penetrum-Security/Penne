import base64
import pathlib
from Crypto.Cipher import AES
import secrets
import datetime as dt
from penne.quarantine.db_create import check_updates

check_updates('https://github.com/Penetrum-Security/Penne', 5)

def spicy_file(path, filename, detection_type, arch):
    print()


def cold_file(sqlitedb, uploaded, encrypted):
    if isinstance(encrypted, bool) and isinstance(uploaded, bool):
        if encrypted and not uploaded and sqlitedb:
            print()
        elif not encrypted and uploaded and not sqlitedb:
            print()
        else:
            print()


def check_prem():
    print()


