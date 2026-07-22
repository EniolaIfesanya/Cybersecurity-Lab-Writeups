# Network Forensics Investigation: JetBrains TeamCity Exploitation (CVE-2024-27198)

# Overview
This write-up documents the network forensics investigation of a compromised JetBrains TeamCity server using a raw packet capture (`Capture.pcap`). The analysis reconstructs the attacker's actions from initial exploitation to an attempted container breakout across 9 key investigation milestones.

---

# Technical Summary

| Milestone | Investigation Step | Finding / Evidence |
| :--- | :--- | :--- |
| **01** | Source IP | Isolated external attacker IP address from packet capture |
| **02** | Target Version | JetBrains TeamCity `2023.11.3` (found in HTTP response headers) |
| **03** | Exploited Vulnerability | `CVE-2024-27198` (Authentication Bypass) |
| **04** | Web Shell File | `.zip` archive containing a malicious `.jsp` web shell |
| **05** | First Execution | Recorded exact UTC timestamp of the first web shell POST request |
| **06** | Command Execution | URL-decoded POST parameters: `whoami`, `ls`, `id` |
| **07** | Credential Tampering | Output redirection to `/tmp/creds.txt` |
| **08** | Stored Artifact | String: `username:a1l4m,password:youarecompromised` |
| **09** | Container Breakout | Command: `docker run --rm -it -v /:/host ubuntu chroot /host` |

---

## Key Attack Phases

### 1. Initial Access & Persistence (CVE-2024-27198)
The adversary targeted an unauthenticated administrative path to upload a `.zip` archive containing a `.jsp` web shell. This provided persistent interactive execution without requiring valid server credentials.

### 2. Reconnaissance & Payload Decoding
Commands sent to the web shell parameter (`cmd=`) were URL-encoded within HTTP POST requests. Decoding the parameters revealed system discovery actions (`whoami`, `ls`, `id`).

### 3. Credential Tampering (MITRE ATT&CK T1565.001)
The attacker executed an encoded command to redirect backdoor credentials into a local file:
```bash
echo "username:a1l4m,password:youarecompromised" > /tmp/creds.txt


4. Container Escape AttempT          
Recognizing they were inside a container, the attacker attempted to mount the host root directory and escape isolation:
docker run --rm -it -v /:/host ubuntu chroot /host
