# VSI Defensive Security Solution
**Team:** Irene LLC | **Client:** Virtual Space Industries (VSI) | **Role:** SOC Analyst

![Splunk](https://img.shields.io/badge/Splunk-SIEM-black?style=for-the-badge&logo=splunk&logoColor=white)
![Vagrant](https://img.shields.io/badge/Vagrant-VM-1868F2?style=for-the-badge&logo=vagrant&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Container-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-Linux-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)

---

## Overview
Irene LLC designed and implemented a defensive security solution for Virtual Space Industries (VSI) using Splunk SIEM. The solution monitors Apache web server and Windows OS logs for malicious activity, generates alerts, and provides dashboards for real-time threat visibility.

---

## Environment
| Component | Details |
|-----------|---------|
| **SIEM** | Splunk Enterprise |
| **VM** | Vagrant + VirtualBox (Ubuntu) |
| **Container** | Docker (Splunk) |
| **Log Sources** | Apache (`access_combined`), Windows (`WinEventLog:Security`) |

---

## Monitoring — Apache Web Server

**Reports**
- HTTP Methods (GET, POST, HEAD)
- Top 10 Referring Domains
- HTTP Response Code Count

**Alerts**
| Alert | Baseline | Threshold |
|-------|----------|-----------|
| International HTTP Activity | 45 | 55 |
| HTTP POST Requests | 2/hr | 5/hr |

**Key SPL Queries**
```splunk
# Top Source IPs
index=apache sourcetype=access_combined | top limit=10 clientip

# Brute Force Detection
index=apache sourcetype=access_combined uri_path="/admin*" method=POST
| bucket _time span=1m | stats count by _time, clientip | where count>20

# Scanner Detection
index=apache sourcetype=access_combined
useragent=*sqlmap* OR useragent=*nikto* | table _time clientip uri_path status
```

---

## Monitoring — Windows OS

**Reports**
- Signature ID Table
- Severity Levels Count & Percentage
- Success vs Failed Activities Comparison

**Alerts**
| Alert | Event ID | Threshold | Severity |
|-------|----------|-----------|----------|
| Failed Logins | 4625 | >10 in 5 min | HIGH |
| Account Lockout | 4740 | Any | CRITICAL |
| Privilege Escalation | 4672 | Outside 8AM–6PM | CRITICAL |
| PowerShell Anomaly | 4688 | Unusual CommandLine | MEDIUM |

**Key SPL Queries**
```splunk
# Failed Logins
index=wineventlog EventCode=4625
| bucket _time span=5m | stats count | where count>10

# Account Lockout
index=wineventlog EventCode=4740 | stats count by TargetUserName

# Privilege Escalation Outside Hours
index=wineventlog EventCode=4672
| where NOT (hour(_time)>=8 AND hour(_time)<=18)
```

---

## Attack Analysis — March 25, 2020

### Apache
| Finding | Detail |
|---------|--------|
| Attack Window | 2:00 PM – 5:00 PM |
| Origin | Kyiv, Ukraine (438 events) & Kharvive, Ukraine (433 events) |
| Method | HTTP POST brute force — `/VSI_Account_logon.php` |
| Volume | **1,296 POST requests** |

**Mitigations**
- Block all HTTP traffic from Kyiv & Kharvive, Ukraine via firewall
- Block any IP generating 5+ POST requests to `/VSI_Account_logon.php`

### Windows
| User | Impact | Time | Signature Peak |
|------|--------|------|---------------|
| User_A | 🔴 Account Locked Out | 12:00 AM – 3:00 AM | 896 events |
| User_K | 🟠 Password Reset Attempt | 8:00 AM – 11:00 AM | 1,256 events |
| User_J | 🔴 Account Compromised | 10:50 AM – 12:30 PM | 196 events |

**Mitigations**
- Lock accounts after 5 failed login attempts
- Block IP after 2 consecutive lockouts from same source
- Enforce MFA on all user accounts
- Blacklist IPs with 3+ failed logins from non-VSI addresses
- Mandate password resets every 90 days

---

## Compliance Alignment
| Framework | Controls Applied |
|-----------|----------------|
| NIST SP 800-61r3 | Incident Response Lifecycle |
| CIS Controls v8 | Account Mgmt (5), Audit Logs (8) |
| OWASP Top 10 (2021) | A01, A03, A07 |

---

## References
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3
- Splunk Apache Add-on: https://docs.splunk.com/AddOns/ApacheWebServer
- Splunk Lantern: https://lantern.splunk.com
- CIS Controls v8: https://cisecurity.org/controls/v8
- OWASP Top 10: https://owasp.org/Top10

---
*Irene LLC — Securing VSI, One Log at a Time*
