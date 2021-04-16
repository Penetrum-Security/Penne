import sqlite3
import base64
import pickle
import pathlib
from Crypto.Cipher import AES
import secrets


def spicy_file(path, filename, detection_type, arch):
    print()

def cold_file(sqlitedb, uploaded, encrypted):
    if isinstance(encrypted, bool) and isinstance(uploaded, bool):
        if encrypted and not uploaded:
            print()
        elif not encrypted and uploaded:
            print()
        else:
            print()