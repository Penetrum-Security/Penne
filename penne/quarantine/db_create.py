import os
import sqlite3
import traceback
from json import load

from termcolor import cprint

from penne.lib.settings import HOME


penne_json = load(open("{}/penne.json".format(HOME), "r"))
penne_db = "{}/{}".format(penne_json['config']['penne_folders']['database_folder'].format(HOME), "strainer.sqlite")
con = sqlite3.connect(penne_db)
cursed = con.cursor()


def first_run():
    try:
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pulls(
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_pull_url TEXT NOT NULL DEFAULT '-',
                        updated_from_github BOOLEAN NOT NULL DEFAULT '-',
                        premium BOOLEAN NOT NULL,
                        FOREIGN KEY (premium) REFERENCES penne_stats(preimum)
        )
                        ''')
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pasta(
                       id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                       date DATETIME default CURRENT_TIMESTAMP,
                       detected_as TEXT NOT NULL DEFAULT '-',
                       original_name TEXT NOT NULL DEFAULT '-',
                       sample_name TEXT NOT NULL DEFAULT '-',
                       sample_origin TEXT NOT NULL DEFAULT '-', 
                       sample_blob BLOB NOT NULL,
                       encrypted BOOLEAN NOT NULL DEFAULT 'true',
                       stored_key TEXT NOT NULL DEFAULT '-',
                       stored_nonce TEXT NOT NULL DEFAULT '-'
        )
                       ''')
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_stats(
                        id INTEGER NOT NULL,
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        execution_time TEXT NOT NULL DEFAULT '-',
                        failure BOOLEAN NOT NULL DEFAULT 'false',
                        preimum BOOLEAN NOT NULL DEFAULT 'false',
                        FOREIGN KEY (id) REFERENCES penne_pasta(id)
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS penne_sigs(
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
            os TEXT NOT NULL DEFAULT '-',
            bytes_read INTEGER NOT NULL DEFAULT 0,
            warning_type TEXT NOT NULL DEFAULT '-',
            sig TEXT UNIQUE,
            sha_hash TEXT UNIQUE,
            detection_name TEXT NOT NULL DEFAULT 'EVIL AF'
        )''')
        con.commit()
        return {
            "Error": '',
            "Success": True,
            "Meanie": False
        }
    except (sqlite3.Error, Exception) as e:
        return {
            "Error": e,
            "TraceBack": traceback.print_exc(),
            "Success": False,
            "Meanie": True
        }


def check_updates(updated_url, pull_from_git, is_premium):
    if updated_url is not None or isinstance(updated_url, str) and isinstance(pull_from_git, bool):
        if is_premium is not None:
            cprint("[ !! ] CHECKING FOR UPDATES [ !! ]", "red", attrs=['bold'])
            try:
                cursed.execute('''INSERT INTO penne_pulls(last_pull_url, updated_from_github, premium) VALUES (?, ?, ?)''',
                               (updated_url, pull_from_git, is_premium,))
                con.commit()
            except sqlite3.OperationalError as e:
                cprint("[ !! ] THERE WAS AN ERROR CONENCTING TO THE DATABASE, BUILDING AND/OR REBUILDING. [ !! ]",
                       "red", attrs=['dark'])
                first_run()
                cursed.execute('''INSERT INTO penne_pulls(last_pull_url, updated_from_github, premium) VALUES (?, ?, ?)''',
                               (updated_url, pull_from_git, is_premium,))
                con.commit()
    else:
        cprint("[ !! ] COULD NOT CHECK FOR UPDATES [ !! ]", "red", attrs=['dark', 'bold'])


def insert_blob(blob_data, blob_name, where_found, original_name, encrypted, need_to_upload, nonce, key, detected_as):
    if isinstance(blob_data, str) and isinstance(blob_name, str) and isinstance(where_found, str) and isinstance(original_name, str) and isinstance(encrypted, bool) and isinstance(detected_as, str):
        if key is None and nonce is None:
            return "Key and Nonce cannot be null"
        else:
            cursed.execute(
                '''INSERT INTO penne_pasta(detected_as, original_name, sample_name, sample_origin, sample_blob, encrypted, stored_key, stored_nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (detected_as, original_name, blob_name, where_found, blob_data, encrypted, key, nonce,))
    elif isinstance(need_to_upload, bool) and need_to_upload is True:
        cprint("[ !! ] UNKNOWN SAMPLE IS BEING UPLOADED, PLEASE WAIT. [ !! ]", "red", "on_white", attrs=['dark', 'bold'])
        return {
            'Upload': True,
            'UploadDest': ''
        }



def create_sig_table():
    for files in os.listdir(penne_json['config']['penne_folders']['unzipped_sigs'].format(HOME)):
        full_path = "{0}/{1}".format(penne_json['config']['penne_folders']['unzipped_sigs'].format(HOME), files)
        with open(full_path) as in_sig:
            for lines in in_sig.readlines():
                split_sig = lines.split(':')
                try:
                    cursed.execute('''INSERT INTO penne_sigs(os, bytes_read, warning_type, sig, sha_hash) VALUES(?, ?, ?, ?, ?)''',
                                   (
                                       split_sig[1],
                                       split_sig[2],
                                       split_sig[3],
                                       split_sig[4],
                                       split_sig[5],
                                   ))
                    con.commit()
                except sqlite3.IntegrityError as e:
                    print("Offending Hash: {}".format(split_sig[5]))
                    print(e)
