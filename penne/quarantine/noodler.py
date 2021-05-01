#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import base64
import datetime
import json
import os.path

import requests
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from termcolor import cprint
from penne.lib.settings import (
    log,
    HOME,
    COMPLETED_RESULTS
)

# check_updates('https://github.com/Penetrum-Security/Penne/version.txt', True, False)


def spicy_file(path, filename, detection_type, arch, detected_as):
    if path is not None and filename is not None and detection_type is not None and detected_as is not None and arch is not None:
        full_path = "{}/{}".format(path, filename)
        cprint("[ !! ] THATS ONE SPICY MEATBALL, TRYING TO COOL IT DOWN [ !! ]", "blue", attrs=['dark', 'bold'])
        key = get_random_bytes(32) # currently limited to 32 bytes, should be strong enough.
        nonce = get_random_bytes(24) # max length for Nonce.
        try:
            if key is not None:
                # Will upgrade to XChaCha_Poly1305 as its more secure than ChaCha20_poly1305
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                # outfiles are stored under the name K-encryption-key__N-nonce__O-original-filename.cold
                outFile = '{}/quarantine/data/cold_files/K-{}__N-{}__O-{}.cold'.format(
                    HOME, str(base64.urlsafe_b64encode(key).decode()), str(base64.urlsafe_b64encode(nonce).decode()),
                    filename.replace(".", "_")
                )
                with open(full_path, "rb") as source, open(outFile, "wb") as dest:
                    for line in source.readlines():
                        # Tag is generated by the chacha20_poly1305 to verify data. we will be using this to verify
                        # any/all data encrypted by penne.
                        ct, tag = cipher.encrypt_and_digest(line)
                        dest.write(ct)
                return {
                    "Success": True,
                    "Encrypted": True,
                    "Uploaded": False,
                    "Key": "{}".format(base64.urlsafe_b64encode(key)),
                    "Nonce": "{}".format(base64.urlsafe_b64encode(nonce)),
                    "Tag": "{}".format(base64.urlsafe_b64encode(tag)),
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
        except TypeError:
            log.critical("unable to encrypt file: {}".format("{}/{}".format(path, filename)))
            COMPLETED_RESULTS["unable_to_cold_store"].append("{}/{}".format(path, filename))
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


def cold_file(user_upload_consent, encrypted, key, nonce, tag, sample):
    if isinstance(encrypted, bool) and isinstance(user_upload_consent, bool) and isinstance(key, str)\
            and isinstance(nonce, str) and isinstance(tag, str) and isinstance(sample, str):
        # only really checking for user upload consent here, as this is where we will flow logic to upload or not.
        if not user_upload_consent:
            from db_create import insert_blob
            cprint("[ !! ] Inserting that spicy meatball into the DB [ !! ]", "red",
                   attrs=['dark'])
        elif user_upload_consent:
            do_check = check_prem()
            if do_check["Success"] is not False:
                cprint("[ !! ] Checking API Key [ !! ]", "blue", attrs=['dark'])
                payload = {
                    "API_KEY": "{}".format(do_check["API_KEY"]),
                    "Sample": "{}".format(sample),
                    "Encrypted": "{}".format(encrypted),
                    "Key": "{}".format(key),
                    "Nonce": "{}".format(nonce),
                    "Tag": "{}".format(tag)
                }
                header = {
                    "Content-Type":"text/json",
                    "Accept": "*/*",
                    "Content-Length": len(payload),
                    "Connection": "Close"
                }
                callOut = requests.get("someurl_that_we_will_fix_later", data=payload, headers=header)
                if callOut.status_code is requests.codes.request_ok:
                    cprint("[ !! ] Request was successful! [ !! ]", "green", attrs=['dark'])
                else:
                    cprint("[ ** ] Something was wrong. {} [ ** ]".format(callOut.status_code), "red", attrs=['dark'])
            else:
                cprint("[ !! ] You need an API key to upload [ !! ]", "red", attrs=['dark'])
        else:
            cprint("[ !! ] Please check your inputs. [ !! ]", "red", attrs=['dark'])


def check_prem():
    from penne.lib.settings import CONFIG_FILE_PATH, download_default_config
    if CONFIG_FILE_PATH is not None or os.path.isfile(CONFIG_FILE_PATH):
        cprint("[ !! ] Appears as though your config is in the right spot! [ !! ]", "blue", attrs=['dark'])
    else:
        cprint("[ + ] YOUR DEFAULT CONFIG IS MISSING. [ + ]", "red", attrs=['dark', 'bold'])
        download_default_config()
    try:
        configfile = json.loads(CONFIG_FILE_PATH)
        api_key = configfile['config']['penne_common']
        if api_key is not None:
            cprint("[ * ] It looks like you have an API key in your config file! Thank you, proceeding.", "blue",
                   attrs=['dark'])
            return {
                "Success": True,
                "API_KEY": api_key['malcore_api_key']
            }
        else:
            cprint("[ !! ] Looks like your API key is not in the config file... :( If you do not have one", "red",
                   attrs=['dark'])
            cprint("Please do not hesitate to get one from https://penetrum.com/ [ !! ]", "red", attrs=['dark'])
            return {
                "Success": False,
                "API_KEY": None
            }
    except Exception as e:
        log.critical("[ !! ] There was an error in check_prem {} [ !! ]".format(e))
        return {
            "Success": False,
            "API_KEY": None
        }


