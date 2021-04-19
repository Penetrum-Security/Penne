import base64
import datetime
import json
import os.path
import sys

from Crypto.Cipher import ChaCha20_Poly1305
import secrets
from termcolor import cprint
from penne.quarantine.db_create import check_updates
from penne.lib.settings import (
    log
)

check_updates('https://github.com/Penetrum-Security/Penne', True, False)


def spicy_file(path, filename, detection_type, arch, detected_as):
    if isinstance(path, str) and isinstance(filename, str) and isinstance(detection_type, str) and isinstance(arch, str):
        cprint("[ !! ] THATS ONE SPICY MEATBALL, TRYING TO COOL IT DOWN [ !! ]", "white", attrs=['dark', 'bold'])
        key = secrets.token_hex(128)
        nonce = secrets.token_hex(64)
        cipher = ChaCha20_Poly1305.new(key, nonce)
        outFile = 'penne/quarantine/data/cold_files/K-' + str(base64.urlsafe_b64encode(key)) + '_N-' + str(base64.urlsafe_b64encode(nonce)) + \
                  "_(" + filename.strip('.') + ").cold"
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
                "Cold_Time": datetime.datetime.now(),
                "Detection": detected_as
            }
        else:
            log.critical("Error when deriving key. The key could not be derived, "
                         "this is a critical error and the application cannot continue.")
            return "Key Derivation failed, this key cannot be null."


def cold_file(sqlitedb, user_upload_consent, encrypted):
    if isinstance(encrypted, bool) and isinstance(user_upload_consent, bool):
        if encrypted and not user_upload_consent and sqlitedb:
            print()
        elif not encrypted and user_upload_consent and not sqlitedb:
            print()
        else:
            print()


def check_prem():
    from penne.lib.settings import CONFIG_FILE_PATH, download_default_config
    if CONFIG_FILE_PATH is not None:
        if os.path.isfile(CONFIG_FILE_PATH):
            configfile = json.loads(CONFIG_FILE_PATH)
            api_key = configfile['config']['penne_common']
            return api_key['malcore_api_key']
        else:
            cprint("[ + ] YOUR DEFAULT CONFIG IS MISSING. [ + ]", "red", attrs=['dark', 'bold'])
            download_default_config()


