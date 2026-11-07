"""libssh authentication-bypass lab ("sshhole", CVE-2018-10933).

A small, realistic SSH server built on libssh 0.8.3 (in the vulnerable
0.8.0-0.8.3 range). It offers password auth and runs commands over an exec
channel once a client is "authenticated". A client can skip authentication
entirely by sending an SSH2_MSG_USERAUTH_SUCCESS message -- a message only a
server should ever send -- which libssh mistakenly accepts, flipping its own
state to authenticated. The reader fires that bypass themselves and runs
commands on the box with no credentials.
"""
import os
import base64

import modal

SLUG = "sshhole"
APP_NAME = "piy-sshhole"
SANDBOX_TIMEOUT = 900

_LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "lab", "sshhole"))

_SOURCES = (
    "deb http://archive.debian.org/debian stretch main\n"
    "deb http://archive.debian.org/debian-security stretch/updates main\n"
)
_B64_SOURCES = base64.b64encode(_SOURCES.encode()).decode()


def _read(name: str) -> str:
    with open(os.path.join(_LAB, name), "r") as f:
        return f.read()


def build_image() -> modal.Image:
    return (
        modal.Image.from_registry("debian:stretch", add_python=None)
        .run_commands(
            "printf '{}' | base64 -d > /etc/apt/sources.list".format(_B64_SOURCES),
            "apt-get -o Acquire::Check-Valid-Until=false update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
            "gcc g++ make cmake pkg-config libc6-dev libssl-dev zlib1g-dev "
            "python3 python3-paramiko openssh-client wget ca-certificates xz-utils",
            # Build libssh 0.8.3 from source (in the vulnerable 0.8.0-0.8.3 range).
            "wget -q https://www.libssh.org/files/0.8/libssh-0.8.3.tar.xz -O /tmp/libssh.tar.xz",
            "cd /tmp && tar xf libssh.tar.xz",
            "cd /tmp/libssh-0.8.3 && mkdir build && cd build && "
            "cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_GSSAPI=OFF "
            "-DWITH_EXAMPLES=OFF -DUNIT_TESTING=OFF .. && "
            "make -j4 && make install && ldconfig",
            "mkdir -p /lab",
        )
        .add_local_file(os.path.join(_LAB, "server.c"), "/lab/server.c", copy=True)
        .add_local_file(os.path.join(_LAB, "exploit.py"), "/lab/exploit.py", copy=True)
        .add_local_file(os.path.join(_LAB, "normal_login.py"), "/lab/normal_login.py", copy=True)
        .run_commands(
            "gcc -o /lab/sshd_vuln /lab/server.c "
            "-I/usr/local/include -L/usr/local/lib -lssh "
            "-Wl,-rpath,/usr/local/lib",
            "ssh-keygen -t rsa -b 2048 -m PEM -f /lab/host_rsa -N '' -q",
        )
        .env({"LD_LIBRARY_PATH": "/usr/local/lib"})
    )


def summary() -> dict:
    return {"slug": SLUG, "title": "The libssh Hole",
            "subtitle": "Tell the server you're already logged in, and it believes you.",
            "cve": "CVE-2018-10933", "meta": "libssh 0.6-0.8.3 \u00b7 disclosed October 2018 \u00b7 authentication bypass"}


def build_lesson() -> dict:
    s = summary()
    s["blocks"] = [
        {"type": "markdown", "content": (
            "SSH is the protocol we trust to guard remote access to servers everywhere. Authentication is the "
            "whole point: you prove who you are \u2014 with a password or a key \u2014 and only then does the server let "
            "you run commands.\n\n"
            "In 2018 it turned out that servers built on **libssh** could be talked past entirely. Not by "
            "guessing a password or stealing a key, but by a client simply *announcing that it had already "
            "succeeded*. Every step below runs against a **real, vulnerable libssh server** we spin up for you "
            "in an isolated sandbox. You\u2019ll walk straight in with no credentials."
        )},
        {"type": "markdown", "content": (
            "## How SSH auth is supposed to go\n\n"
            "After the encrypted channel is set up (the key exchange), the **client** sends "
            "`SSH2_MSG_USERAUTH_REQUEST` with its username and password. The **server** checks it and, only if "
            "it\u2019s valid, replies with `SSH2_MSG_USERAUTH_SUCCESS`. That success message is the server\u2019s to "
            "send \u2014 the client is only ever supposed to *receive* it."
        )},
        {"type": "markdown", "content": (
            "## The victim: a normal libssh server\n\n"
            "Here is our target. It\u2019s a small but realistic SSH server: it accepts a password for user `admin`, "
            "and once a client is authenticated it runs the command they ask for over an exec channel. Like most "
            "libssh servers, it trusts the library to enforce authentication and only wires up its own "
            "channel/exec handlers \u2014 notice it never re-checks auth itself before running your command."
        )},
        {"type": "code", "language": "c", "title": "server.c", "content": _read("server.c")},
        {"type": "markdown", "content": (
            "## Step 1 \u2014 Start the vulnerable server\n\n"
            "Boot it inside your sandbox. It listens on port 2022, built against libssh 0.8.3 \u2014 a version from "
            "before the bug was fixed."
        )},
        {"type": "run", "title": "Start the SSH server", "kind": "background", "logfile": "/tmp/sshd.log",
         "command": "/lab/sshd_vuln 2022",
         "explain": "Launches the libssh server as a background process; its log streams to /tmp/sshd.log."},
        {"type": "markdown", "content": (
            "## Step 2 \u2014 Knock on the door the honest way\n\n"
            "First behave like a normal client and log in with the wrong password. The server does exactly what "
            "you\u2019d expect: it refuses you. Authentication clearly works."
        )},
        {"type": "run", "title": "Log in with a wrong password", "kind": "foreground",
         "command": "python3 /lab/normal_login.py 127.0.0.1 2022 admin letmein 'id'",
         "explain": "A well-behaved SSH client authenticating with a bogus password. Access is denied."},
        {"type": "markdown", "content": (
            "## The trick\n\n"
            "Now the exploit. Instead of sending a `USERAUTH_REQUEST` and waiting to be judged, our client sends "
            "the server a `SSH2_MSG_USERAUTH_SUCCESS` message itself \u2014 the one only a server is meant to send. A "
            "vulnerable libssh server receives it, its state machine concludes \u201cauthentication is done\u201d, and it "
            "starts serving channels. We never sent a username or a password."
        )},
        {"type": "code", "language": "python", "title": "exploit.py", "content": _read("exploit.py")},
        {"type": "markdown", "content": (
            "## Step 3 \u2014 Walk straight in\n\n"
            "Run the exploit. It completes the key exchange, sends the forged success message, opens a channel, "
            "and runs a command \u2014 all without a single credential."
        )},
        {"type": "run", "title": "Bypass auth and run a command", "kind": "foreground",
         "command": "python3 /lab/exploit.py 127.0.0.1 2022 'id > /tmp/pwned; whoami >> /tmp/pwned; hostname >> /tmp/pwned; uname -a >> /tmp/pwned'",
         "explain": "No password, no key. The server runs our command and writes its output to /tmp/pwned."},
        {"type": "markdown", "content": (
            "## Step 4 \u2014 Proof of remote code execution\n\n"
            "The exploit ran a command *as the server process* and wrote the result to . Read "
            "it. The uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo),109(kvm),998(docker) output below proves the attacker just ran arbitrary commands on the server \u2014 "
            "without ever sending a username or a password."
        )},
        {"type": "run", "title": "Read the proof", "kind": "foreground",
         "command": "cat /tmp/pwned",
         "explain": "Written by the attacker\u2019s command, executing inside the victim."},
        {"type": "markdown", "content": (
            "## What just happened\n\n"
            "The server ran our command as its own user because libssh believed we had authenticated \u2014 on the "
            "strength of a message we had no business sending. Any libssh-based server that trusted the library "
            "to gate access (SFTP servers, git-over-SSH frontends, network appliances) could be walked into the "
            "same way.\n\n"
            "## The fix\n\n"
            "libssh **0.7.6** and **0.8.4** fixed it: the server side now ignores `USERAUTH_SUCCESS` (and other "
            "messages a client should never originate) instead of treating it as a valid state transition. The "
            "recurring lesson of this site holds here too \u2014 a state machine that accepts input it should only "
            "ever *produce* is an open door."
        )},
    ]
    return s
