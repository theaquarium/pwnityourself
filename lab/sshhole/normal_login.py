#!/usr/bin/env python3
"""A well-behaved SSH client, for the baseline step.

It connects and authenticates the normal way. Run it with the wrong password
and the server refuses you -- proof that the box does require credentials
before the bypass makes a mockery of them.

Usage: normal_login.py <host> <port> <user> <password> [command]
"""
import sys

import paramiko


def login(host, port, user, password, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       allow_agent=False, look_for_keys=False, timeout=15,
                       banner_timeout=15)
    except paramiko.AuthenticationException:
        print("[server] authentication failed for user '{}' -- access denied.".format(user))
        return 1
    print("[*] authenticated as '{}'. Running: {}".format(user, command))
    _, stdout, stderr = client.exec_command(command)
    sys.stdout.write(stdout.read().decode(errors="replace"))
    sys.stderr.write(stderr.read().decode(errors="replace"))
    client.close()
    return 0


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2022
    user = sys.argv[3] if len(sys.argv) > 3 else "admin"
    password = sys.argv[4] if len(sys.argv) > 4 else "letmein"
    command = sys.argv[5] if len(sys.argv) > 5 else "id"
    sys.exit(login(host, port, user, password, command))
