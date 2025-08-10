---
title: "OSI Layer Enumeration Cheat Sheet"
description: "Practical enumeration techniques for each OSI model layer, with real Hack The Box tie-ins."
tags: [OSI, Enumeration, Pentesting, HTB, Networking, Cybersecurity]
author: "Julian West"
date: 2025-08-09
---

# OSI Layer Enumeration Cheat Sheet

## Layer 1 – Physical
*(Mostly outside HTB scope, but for real-world awareness)*  
**Goal:** Verify physical connectivity or simulate physical access  
**Tools/Methods:**  
- Check cable connectivity (real-world only)  
- RF / Wi-Fi signal mapping (e.g., `airmon-ng`, `airodump-ng`)  
- Hardware implant drops (LAN taps, not in HTB)  

---

## Layer 2 – Data Link
**Goal:** Interact with local network segments (MAC-level)  
**Tools/Methods:**  
- `arp -a` → view ARP table  
- `arp-scan` → detect hosts on LAN  
- VLAN enumeration → `vlan-hopping` tools, `yersinia`  
- MAC spoofing → `macchanger`  
**HTB tie-in:** Rare unless box simulates a local network attack.

---

## Layer 3 – Network
**Goal:** Discover reachable targets and IP mappings  
**Tools/Methods:**  
- `ping`, `traceroute` / `tracert`  
- Host mapping: `echo "10.x.x.x planning.htb" >> /etc/hosts`  
- ICMP sweep: `nmap -sn 10.10.10.0/24`  
- VPN tunnel verification for HTB labs  
**HTB tie-in:** Adding `planning.htb` to `/etc/hosts` before enumeration.

---

## Layer 4 – Transport
**Goal:** Identify and confirm service ports  
**Tools/Methods:**  
- Full TCP scan: `nmap -p- -T4 target`  
- Common port scan: `nmap -p 21,22,80,443,3306,5432 target`  
- Banner grabbing: `nc target 22` or `curl -v telnet://target:port`  
- Service probes: `nmap -sV target`  
**HTB tie-in:** Seeing MySQL (3306) and PostgreSQL (5432) services on `planning.htb`.

---

## Layer 5 – Session
**Goal:** Manipulate and maintain sessions/authentication  
**Tools/Methods:**  
- Capture cookies: Burp Suite, browser dev tools, `curl -b`  
- Replay sessions: `curl -H "Cookie: ..." target`  
- Hijack tokens: look for JWT or session IDs in responses  
- Test for session fixation/logout flaws  
**HTB tie-in:** Reusing auth tokens for Grafana API requests.

---

## Layer 6 – Presentation
**Goal:** Handle data encoding/decoding, encryption  
**Tools/Methods:**  
- JSON parsing: `jq`, Python scripts  
- Base64: `echo ... | base64 -d`  
- URL encoding: `urldecode`, `curl --data-urlencode`  
- SSL/TLS info: `openssl s_client -connect target:443`  
**HTB tie-in:** Parsing JSON Grafana output, decoding `%40` to `@`.

---

## Layer 7 – Application
**Goal:** Enumerate and exploit application logic  
**Tools/Methods:**  
- **Web enumeration:** `gobuster`, `ffuf`  
- **API probing:** `curl` requests to `/api/` endpoints  
- **Form fuzzing:** Burp Intruder, `ffuf` POST body injection  
- **Vulnerability scanning:** `wpscan`, `nikto`, `sqlmap`  
- **CMS-specific:** XWiki, Grafana, WordPress  
**HTB tie-in:**  
- Finding `grafana.planning.htb` with `gobuster vhost`  
- Enumerating `/api/datasources` to find MySQL & PostgreSQL  

---

## Pro Tip – Layer-Jumping Enumeration
- **Start low:** Verify target is up (Layer 3) → check open ports (Layer 4)  
- **Move up:** Try interacting with services directly (Layer 5–7)  
- **Drop back down:** If stuck at a web app, look for alternate service ports that might bypass application-layer restrictions.
