from flask import g
import psycopg2
from psycopg2.extras import DictCursor


#def connect_db():
#    sql = sqlite3.connect('qanda.db')
#    sql.row_factory = sqlite3.Row
#    return sql
#
#
#def get_db():
#    if not hasattr(g, 'sqlite_db'):
#        g.sqlite_db = connect_db()
#    return g.sqlite_db


def connect_db():
    conn = psycopg2.connect(r'postgres://raufbxqniscxpm:56e6947a5a9765c9c37621b6baeb22445fb119a0e7b913bd1b7ac01238f151da@ec2-3-232-240-231.compute-1.amazonaws.com:5432/d4fthmhvvcl2tu',
                            cursor_factory=DictCursor)
    conn.autocommit = True
    cur = conn.cursor()
    return conn, cur


def get_db():
    db = connect_db()
    if not hasattr(g, 'postgres_db_conn'):
        g.postgres_db_conn = db[0]

    if not hasattr(g, 'postgres_db_cur'):
        g.postgres_db_cur = db[1]

    return g.postgres_db_cur


def init_db():
    db = connect_db()
    db[1].execute(open('schema.sql', 'r').read())
    db[1].close()
    db[0].close()


def init_admin():
    db = connect_db()
    db[1].execute("UPDATE users SET admin = '1' WHERE name = %s", ('admin', ))
    db[1].close()
    db[0].close()
