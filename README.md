# Cybersecurity-Lab-Writeups
# Network Forensics Analysis: JetBrains TeamCity Exploitation

##  Summary
This write-up documents the network forensics investigation of a compromised JetBrains TeamCity server using a raw packet capture (`Capture.pcap`). The analysis traces the adversary's lifecycle from the initial web shell deployment, through active reconnaissance, credential tampering, and a subsequent container escape attempt.

---

## Analysis & Incident Timeline

### Phase 1: Initial Exploitation & Persistent Access
 **Vector:** The adversary targeted a file upload capability within the TeamCity management interface.
 **Evidence:** Analysis of HTTP traffic revealed a suspicious file upload via a `POST` request directed at `/admin/pluginUpload.html`. The payload consisted of a malicious `.jsp` web shell compressed inside a `.zip` archive.
 **Analysis Insight:** This allowed the attacker to establish an interactive execution environment within the web server's context without needing valid SSH or remote desktop credentials.

### Phase 2: Reconnaissance & Web Shell Interaction
 **Vector:** Interactive command execution via the deployed web shell.
 **Evidence:** The adversary interacted with the uploaded backdoor by sending standard HTTP `POST` requests to `/plugins/NSt8bHTg/NSt8bHTg.jsp`. System commands were passed through the `cmd=` parameter. 
 **Analysis Insight:** Because commands are transmitted via standard HTTP forms, the payloads were URL-encoded (e.g., spaces converted to `+` or `%20`, and specific operators converted to hex values). Analysts must decode these strings to reveal discovery actions like `whoami` and `ls`.

### Phase 3: Credential Tampering (Actions on Objectives)
 **Vector:** Stored Data Manipulation (MITRE ATT&CK T1565.001).
 **Evidence:** The adversary attempted to establish a persistent backdoor credential set by executing an encoded string that translates to:
  ```bash
  echo "username:a1l4m,password:youarecompromised" > /tmp/creds.txt

  Analysis Insight: Rather than scanning text streams manually, this activity can be isolated within a PCAP by searching packet bytes globally for generic Linux output redirection operators (> or %3E) combined with writable directories like /tmp.

Phase 4: Container Escape Attempt
Vector: Privilege Escalation via Docker Volume Mount.

Evidence: Recognizing they were isolated within a container, the adversary executed a classic breakout command via the web shell parameter:
docker run --rm -it -v /:/host ubuntu chroot /host
Analysis Insight: The attacker utilized the -v /:/host flag to map the underlying host operating system's root directory (/) into the container's file system at /host. Using chroot, they attempted to pivot their root context to the host, bypassing container isolation boundaries.

Key Blue Team Takeaways & Detection Indicators
Web Shell Hunting: Monitor web application logs and network traffic for unusual POST requests targeting newly created or deep plugin paths (e.g., /plugins/*/*.jsp), especially when paired with execution parameters like cmd=, exec=, or shell=.

URL-Decoding Pipelines: Threat hunting workflows must incorporate URL-decoding layers; raw PCAP bytes will obscure human-readable command flags behind hex codes.

Container Escape Signatures: Alert on container infrastructure traffic containing interactive Docker commands utilizing root volume mapping flags (-v /:/ or --volume /:/), which serves as a high-fidelity indicator of an active breakout attempt.
