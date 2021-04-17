import sqlite3
import sys
import traceback
from termcolor import cprint


con = sqlite3.connect("penne/data/strainer.db")
cursed = con.cursor()

def first_run():
    try:
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pulls(
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_pull_url TEXT NOT NULL DEFAULT '-',
                        updated_from_github TEXT NOT NULL DEFAULT '-'
        )
                        ''')
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_pasta(
                       id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                       date DATETIME default CURRENT_TIMESTAMP, 
                       sample_origin TEXT NOT NULL DEFAULT '-', 
                       sample_blob BLOB NOT NULL
        )
                       ''')
        con.execute('''
        CREATE TABLE IF NOT EXISTS penne_stats(
                        id INTEGER NOT NULL,
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        execution_time TEXT NOT NULL DEFAULT '-',
                        failure TEXT NOT NULL DEFAULT 'false',
                        preimum TEXT NOT NULL DEFAULT 'false',
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


def check_updates(date_today):
    if date_today is not None or isinstance(date_today, str):
        cprint("[ !! ] CHECKING FOR UPDATES [ !! ]", "blue", "on_white", attrs=['dark', 'bold'])
