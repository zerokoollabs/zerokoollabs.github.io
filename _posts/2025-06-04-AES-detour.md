---
layout: post
title: "AES Detour"
date: 2025-06-04
author: zerokoollabs
tags: [kerberos, impacket, aes, redteam, htb]
---

# 🔐 HTB *Archetype* Detour: What mssqlclient.py's -aesKey Option Taught Me

*"You can know the name of a bird in all the languages of the world, but when you're done, you'll know absolutely nothing whatever about the bird... So let's look at the bird and see what it's doing — that's what counts." — Richard Feynman*

In working through the HTB box _Archetype_, I took a detour.

The write-up and walkthrough were straightforward: dump credentials from SMB, connect to MSSQL with Impacket, enable `xp_cmdshell`, get a reverse shell, escalate to Administrator. Done.

Initially, in the hack, you simply use `mssqlclient.py` to authenticate into the server, using the plain text password. I found it in the backup file.  The official Hack the Box writeup showed the help screen for mssqlclient.py.  One of the flags was `-aesKey`.  I thought I'd play around with the `-aesKey` flag.  After all, in the cyberworld, you're far more likely to find such an encrypted key than a plain text password.  

```bash
python3 mssqlclient.py -aesKey [AES KEY HERE]
```

Well, I couldn't play around with the flag itself ..... didn't have an "aesKey" to pass.  Guess I have to make my own.  I used the text password and wrote a simple script to derive an AES key.

---

## 🧪 The Python Script: Deriving the AES-256 Key

```python
from impacket.krb5.crypto import _AES256CTS

# Inputs
username = "sql_svc"
domain = "HTB.LOCAL"
password = "M3g4c0rp123"

# Kerberos salt = UPPERCASE_REALM + username
salt = domain.upper() + username
print("This is the salt:")
print(salt)

# Derive AES256 key
key = _AES256CTS.string_to_key(password.encode(), salt.encode(), None)
print(key)
print("All attributes and methods:")
print(dir(key))        # Shows all attributes and methods
print("Internal properties:")
print(key.__dict__)    # Shows internal properties, if any.
print("AES256 Key:")  
print(key.contents.hex())  # Output the AES key in hex.
print([hex(b) for b in key.contents]) # Make it more recognizable to read.
```

### 🔍 What This Script Does

- Uses Impacket’s internal Kerberos crypto module
    
- Applies Microsoft's Kerberos key derivation routine for AES-256-CTS
    
- Constructs the **salt** as `UPPERCASE_REALM + username`
    
- Prints out the 256-bit key in hex
    

**Output:**

I'm not going to get into the output from "`print(key_dict_)I`" ... You may want to investigate that yourself.  I'm gong to focus on the actual key output and the printout of the key in hex.  (The comments in the script point to the function of the commands.)

```bash
AES256 Key:
16d02cdf915afefd4e034b98889149e5856515fb6ee11499f009a55215652a75

Internal properties:
{'enctype': 18, 'contents': b'\x16\xd0,\xdf\x91Z\xfe\xfdN\x03K\x98\x88\x91I\xe5\x85e\x15\xfbn\xe1\x14\x99\xf0\t\xa5R\x15e*u'}
['0x16', '0xd0', '0x2c', '0xdf', '0x91', '0x5a', '0xfe', '0xfd', '0x4e', '0x3', '0x4b', '0x98', '0x88', '0x91', '0x49', '0xe5', '0x85', '0x65', '0x15', '0xfb', '0x6e', '0xe1', '0x14', '0x99', '0xf0', '0x9', '0xa5', '0x52', '0x15', '0x65', '0x2a', '0x75']
```

**This** is what you'd pass into `-aesKey` when connecting to MSSQL (or other Kerberos-aware services) without needing the password.

---

## 🧠 But What Does That Byte String _Mean_?

The raw key looked like this before `.hex()`:

```python
b'\x16\xd0\x2c\xdf...'
```

Each `\x..` is a **byte**, or 8 bits. The key is 32 bytes (256 bits), which matches AES-256.

I explored the `Key` object:

```python
print(key)
# <impacket.krb5.crypto.Key object at 0x...>

print(key.__dict__)
# {'enctype': 18, 'contents': b'...'}
```

- `contents` is the actual key
    
- `enctype: 18` = AES256-CTS-HMAC-SHA1-96 (standard Kerberos encryption)
    

Let's take a closer look at the`enctype`values are assigned by IANA, and `18` is the registered value for AES256 in Kerberos.  Below is a list of Kerberos Encryption types and their IANA codenames.

---

## 🔢 Common Kerberos Encryption Types

| ID  | Name                                 | Key Size | Description |
|-----|--------------------------------------|----------|-------------|
| 0   | `NULL`                               | N/A      | No encryption |
| 1   | `DES-CBC-CRC`                        | 56-bit   | Deprecated (very weak) |
| 2   | `DES-CBC-MD4`                        | 56-bit   | Deprecated |
| 3   | `DES-CBC-MD5`                        | 56-bit   | Deprecated |
| 16  | `DES3-CBC-SHA1`                      | 168-bit  | Triple DES (deprecated) |
| 17  | `AES128-CTS-HMAC-SHA1-96`            | 128-bit  | Common in modern Windows domains |
| **18**  | **`AES256-CTS-HMAC-SHA1-96`**    | 256-bit  | Preferred and secure for Kerberos tickets |
| 23  | `RC4-HMAC`                           | 128-bit  | Legacy AD environments (weak, but common) |
| 24  | `RC4-HMAC-EXP`                       | 40-bit   | Export-grade (extremely weak) |
| 25  | `Camellia128-CTS-CMAC`               | 128-bit  | Optional algorithm |
| 26  | `Camellia256-CTS-CMAC`               | 256-bit  | Optional algorithm |
| 65  | `AES128-CTS-HMAC-SHA256-128`         | 128-bit  | Stronger SHA-2 variant (modern Windows) |
| 66  | `AES256-CTS-HMAC-SHA384-192`         | 256-bit  | Stronger SHA-2 variant (Windows Server 2022+) |

---

These `enctype` values are ***embedded*** in **Kerberos tickets**, **LSASS memory dumps**, and **keytab files** and are used by security tools like Impacket to identify the encryption algorithm.  This detail helps identify whether the given environment you're encapsulating is **up-to-date or using legacy encryption**, a real help in finding an effective exploit angle.

---

## 🧠 Lessons from the Detour

- `-aesKey` is not some obscure Impacket feature — it reflects a real-world attack path (pass-the-key)
    
- Kerberos key derivation uses predictable logic (password + salt)
    
- Python objects like `Key` may hold hidden details in their attributes
    
- A byte string like `\x16\xd0...` is just binary data — and `.hex()` is your friend

## 🔐 Why This Matters in Real Engagements
At some point, I’ll likely encounter an HTB lab where I’ll need to apply this knowledge — deriving a password from Kerberos-encrypted data. This detour has deepened my understanding of how Kerberos can be targeted by adversaries, and more importantly, how to anticipate, detect, and defend against such attacks. I’m glad I let my curiosity roam. Now, when I see a Kerberos key or ticket, I understand what it means — and how it fits into the broader authentication process.