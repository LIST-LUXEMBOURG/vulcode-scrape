# © 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved
# This software is licensed under GPL V3.0 Licence -  https://www.gnu.org/licenses/gpl-3.0.txt

import sqlite3
import sys
from sqlite3 import Error


def create_connection(database_file):
    try:
        return sqlite3.connect(database_file, timeout=10)
    except Error as e:
        sys.exit(e)


def table_exists(conn, table_name):
    """
    checks whether table exists or not
    :returns boolean yes/no
    """
    query = ("SELECT name FROM sqlite_master WHERE TYPE='table' AND name='" + table_name + "';")
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    if result is not None:
        return True
    else:
        return False


def fetch_one_query(db, table_name, col, value):
    """
    check whether a table exists or not
    """
    query = ("SELECT " + col + " FROM " + table_name + " WHERE repo_url='" + value + "'")
    cursor = db.cursor()
    cursor.execute(query)
    result = cursor.fetchone()

    return True if result is not None else False