#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import base64
import datetime
import json
import os.path

from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from termcolor import cprint
from penne.quarantine.db_create import check_updates
from penne.lib.settings import (
    log,
    HOME
)

# check_updates('https://github.com/Penetrum-Security/Penne', True, False)


def spicy_file(path, filename, detection_type, arch, detected_as):
    if path is not None and filename is not None and detection_type is not None and detected_as is not None and arch is not None:
        full_path = "{}/{}".format(path, filename)
        cprint("[ !! ] THATS ONE SPICY MEATBALL, TRYING TO COOL IT DOWN [ !! ]", "white", attrs=['dark', 'bold'])
        key = get_random_bytes(32)
        nonce = get_random_bytes(24)
        if key is not None:
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            outFile = '{}/quarantine/data/cold_files/K-{}_N-{}_({}).cold'.format(
            HOME, str(base64.urlsafe_b64encode(key).decode()), str(base64.urlsafe_b64encode(nonce).decode()),
                filename.replace(".", "_")
            )
            with open(full_path, "rb") as source, open(outFile, "wb") as dest:
                for line in source.readlines():
                    dest.write(cipher.encrypt(line))
            return {
                "Success": True,
                "Encrypted": True,
                "Uploaded": False,
                "Key": f"{base64.urlsafe_b64encode(key)}",
                "Nonce": f"{base64.urlsafe_b64encode(nonce)}",
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
            return {
                "Success": False,
                "Encrypted": False,
                "Uploaded": False,
                "Key": None,
                "Nonce": None,
                "ColdFile": None,
                "Original_File": filename,
                "Found_where": path,
                "DetectedAs": detection_type,
                "Cold_Time": datetime.datetime.now(),
                "Detection": detected_as
            }


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


