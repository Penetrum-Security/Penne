import base64
import datetime
import os.path
import pathlib
from Crypto.Cipher import ChaCha20_Poly1305
import secrets
from termcolor import cprint
import datetime as dt
from penne.quarantine.db_create import check_updates
import json

check_updates('https://github.com/Penetrum-Security/Penne', True)


def spicy_file(path, filename, detection_type, arch):
    if isinstance(path, str) and isinstance(filename, str) and isinstance(detection_type, str) and isinstance(arch, str):
        cprint("[ !! ] THATS ONE SPICY MEATBALL, TRYING TO COOL IT DOWN [ !! ]", "white", "on_blue", attrs=['dark', 'bold'])
        key = secrets.token_hex(128)
        nonce = secrets.token_hex(64)
        cipher = ChaCha20_Poly1305.new(key, nonce)
        outFile = './cold_files/'+str(base64.urlsafe_b64encode(key)) + '_' + str(base64.urlsafe_b64encode(nonce)) + "_" + filename + ".cold"
        if key is not None:
            with open(path+filename, "rb") as spicy:
                for line in spicy.readlines():
                    cText = cipher.encrypt(line)
            with open(outFile, 'ab') as not_so_spicy:
                not_so_spicy.writelines(cText)
            return {
                "Success": True,
                "Encrypted": True,
                "Uploaded": False,
                "Key": key,
                "Nonce": nonce,
                "ColdFile": outFile,
                "Original_File": filename,
                "Found_where": path,
                "DetectedAs": detection_type,
                "Cold_Time": datetime.datetime.now()
            }
        else:
            print("Coming soon.")


def cold_file(sqlitedb, uploaded, encrypted):
    if isinstance(encrypted, bool) and isinstance(uploaded, bool):
        if encrypted and not uploaded and sqlitedb:
            print()
        elif not encrypted and uploaded and not sqlitedb:
            print()
        else:
            print()


def check_prem(config):
    from penne.lib.settings import CONFIG_FILE_PATH
    if CONFIG_FILE_PATH is not None:
        if os.path.isfile(CONFIG_FILE_PATH):




