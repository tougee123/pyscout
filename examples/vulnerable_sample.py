"""Intentionally insecure sample for testing pyscout. Do not use as real code."""

import os
import pickle
import sqlite3
import subprocess

API_KEY = "sk-live-1234567890abcdef"  # hardcoded secret


def ping(host):
    # command injection: host flows into a shell
    os.system("ping -c 1 " + host)


def run(cmd):
    return subprocess.call(cmd, shell=True)


def get_user(db_path, username):
    conn = sqlite3.connect(db_path)
    # SQL injection: string-built query
    return conn.execute("SELECT * FROM users WHERE name = '" + username + "'").fetchall()


def load_blob(data):
    # unsafe deserialization of untrusted input
    return pickle.loads(data)


def read_any(user_path):
    # path traversal: no validation on user_path
    with open("/data/" + user_path) as f:
        return f.read()
