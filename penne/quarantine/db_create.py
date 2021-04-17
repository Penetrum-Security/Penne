import sqlite3
import sys
import traceback
from termcolor import cprint


con = sqlite3.connect("data/strainer.sqlite")
cursed = con.cursor()


def first_run():
    try:
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pulls(
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_pull_url TEXT NOT NULL DEFAULT '-',
                        updated_from_github BOOLEAN NOT NULL DEFAULT '-'
        )
                        ''')
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pasta(
                       id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                       date DATETIME default CURRENT_TIMESTAMP,
                       original_name TEXT NOT NULL DEFAULT '-',
                       sample_name TEXT NOT NULL DEFAULT '-',
                       sample_origin TEXT NOT NULL DEFAULT '-', 
                       sample_blob BLOB NOT NULL,
                       encrypted BOOLEAN NOT NULL DEFAULT 'true',
                       stored_key TEXT NOT NULL DEFAULT '-'
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
        )
                        ''')
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


def check_updates(updated_url, pull_from_git):
    if updated_url is not None or isinstance(updated_url, str) and isinstance(pull_from_git, bool):
        cprint("[ !! ] CHECKING FOR UPDATES [ !! ]", "red", "on_blue", attrs=['bold'])
        try:
            cursed.execute('''INSERT INTO penne_pulls(last_pull_url, updated_from_github) VALUES ('?', '?')''', (updated_url, pull_from_git))
            con.commit()
        except sqlite3.OperationalError as e:
            cprint("[ !! ] THERE WAS AN ERROR CONENCTING TO THE DATABASE, BUILDING AND/OR REBUILDING. [ !! ]",
                   "red", "on_white", attrs=['dark', 'bold'])
            first_run()
            cursed.execute('''INSERT INTO penne_pulls(last_pull_url, updated_from_github) VALUES ('?', '?')''' , (updated_url, pull_from_git))
            con.commit()
    else:
        cprint("[ !! ] COULD NOT CHECK FOR UPDATES [ !! ]", "red", "on_white", attrs=['dark', 'bold'])


def insert_blob(blob_data, blob_name, where_found, original_name, encrypted, need_to_upload):
    if isinstance(blob_data, str) and isinstance(blob_name, str) and isinstance(where_found, str) and isinstance(original_name, str) and isinstance(encrypted, bool):
        cursed.execute('''INSERT INTO penne_pasta(original_name, sample_name, sample_origin, sample_blob, encrypted) VALUES ('?', '?', '?', '?', '?')''', (original_name, blob_name, where_found, blob_data, encrypted))
    elif isinstance(need_to_upload, bool) and need_to_upload is True:
        cprint("[ !! ] UNKNOWN SAMPLE IS BEING UPLOADED, PLEASE WAIT. [ !! ]", "red", "on_white", attrs=['dark', 'bold'])
        return {
            'Upload': True,
            'UploadDest': ''
        }
