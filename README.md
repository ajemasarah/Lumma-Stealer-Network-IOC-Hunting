Incident Analysis Report: Lumma Stealer Network IOC Hunting

📋 Executive Summary
This repository details the packet analysis (`.pcap`) investigation of a network traffic capture. Using `Wireshark`, the investigation traced malicious activity from initial host communication and directory enumeration through `Kerberos` and `SAMR` protocols, ultimately identifying an active Command & Control (C2) beacon communicating with a malicious external domain (`whitepepper.su`). Threat intelligence validation via `VirusTotal` confirmed the external destination as malicious.

---

🔍 Investigation Overview

Phase 1: Network Triage & Host Profiling
Initial inspection of the packet capture (`2026-01-31-traffic analysis exercise.pcap`) revealed local DHCP transactions and NBNS broadcasts establishing the workstation's identity.
* DHCP / IP Assignment:** Workstation assigned IP `10.1.21.58` via DHCP server `10.1.21.1`.
* Hostname Identification:** DHCP options and NBNS traffic identified the target machine as `DESKTOP-ES9F3ML`.


> **Evidence:**
> ![DHCP & Host Discovery](images/Screenshot_2026-10-26_22_04_37.png)


Phase 2: Authentication & Account Discovery (Kerberos & SAMR)
Filtering internal protocol traffic uncovered active user session activity and enumeration queries.
* Kerberos Activity:** Multiple AS-REQ and TGS-REQ exchanges were observed involving user account `gwyatt` under domain `WIN11OFFICE`.
* SAMR Enumeration:** Security Account Manager Remote (SAMR) protocol queries (`QueryUserInfo`) executed against domain controller `10.1.21.2` revealed details of the target user profile.
  * Target Account Name:** `Gabriel Wyatt`

> **Evidence:**
> * Kerberos Ticket Requests: ![Kerberos Analysis](02-kerberos-gwyatt.png)
> * SAMR User Enumeration: ![SAMR Enumeration](04-samr-user-enum.png)


Phase 3: Command & Control (C2) Traffic Analysis
Filtering HTTP traffic (`http.host contains "whitepepper"`) exposed external communication with suspicious infrastructure.
* Source IP:** `10.1.21.58` (Compromised Workstation)
* Destination IP / Domain:** `153.92.1.49` / `whitepepper.su`
* URI Pattern:** GET and POST requests to `/api/set_agent?id=3BF67EC05320C5729578...` indicating active beaconing/check-in behavior.

> **Evidence:**
> ![HTTP C2 Beaconing](05-http-c2-traffic.png)



Phase 4: Threat Intelligence Verification
The suspicious domain and URL path were evaluated against **VirusTotal** for threat vendor detections.
* Target Endpoint:** `http://whitepepper.su/api/set_agent`
* Vendor Consensus:** High-risk detection score across major engines (BitDefender, AlphaSOC, etc.).
* Threat Classification:** Malicious C2 / Phishing Infrastructure.

> **Evidence:**
> ![VirusTotal Detection](06-virustotal-verdict.png)

---

🛡️ Key Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |

| **Domain** | `whitepepper.su` | Command & Control (C2) Host |
| **IP Address** | `153.92.1.49` | External C2 Infrastructure |
| **User Account** | `gwyatt` (Gabriel Wyatt) | Compromised Domain User |
| **Hostname** | `DESKTOP-ES9F3ML` | Internal Affected Host |
| **URI Endpoint** | `/api/set_agent` | Agent Check-in Route |

---
*Report published as part of SOC threat hunting and network forensics practice.*
