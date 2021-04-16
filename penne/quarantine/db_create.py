import sqlite3
import sys
import traceback


def first_run():
    try:
        con = sqlite3.connect("penne/data/strainer.db")
        con.execute('''CREATE TABLE IF NOT EXISTS penne_pasta(
                       id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                       date DATETIME default CURRENT_TIMESTAMP, 
                       sample_origin TEXT NOT NULL DEFAULT '-', 
                       sample_blob BLOB NOT NULL)
                       ''')
        con.execute('''CREATE TABLE IF NOT EXISTS penne_stats(
                        id INTEGER NOT NULL,
                        datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                        execution_time TEXT NOT NULL DEFAULT '-',
                        failure TEXT NOT NULL DEFAULT 'false',
                        preimum TEXT NOT NULL DEFAULT 'false',
                        FOREIGN KEY (id) REFERENCES penne_pasta(id)
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
            "Stack Trace": sys.exc_info()[0],
            "Other Exception  Info": sys.gettrace(),
            "Success": False,
            "Meanie": True
        }
