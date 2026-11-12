# Alert 03. Suspected phishing email

**Source:** Sample from the public phishing_pot dataset, file [sample-10407.eml]
**Environment:** Analysed as plain text. I did not open any link or attachment.
**Tools:** Notepad, VirusTotal URL scan

## What fired
An email with a generic display name, a fake confirmation subject and a
body made only of images that link to a shortened URL.

## What I checked
1. Sender and display name.
2. Return-Path and Reply-To against the From address.
3. SPF, DKIM and DMARC results.
4. The first server in the Received chain, read from the bottom up.
5. The links in the HTML body.
6. The reputation and redirect chain of the link, using VirusTotal.

## Evidence

**Headers**
- From: display name "#Thank_You*" using a Gmail address,
  riribough6[@]gmail[.]com. The name and the subject
  "#Confirmation-10928*Rlk9#" match no real company.
- No Reply-To. Return-Path is a Google Groups list address on a
  cheap domain, because the message passed through mailing lists.
  This explains why it differs from the From address.
- At the first Google hop, SPF, DKIM and DMARC all passed for gmail.com.
  At the final hop, SPF was none and DMARC failed (policy none). The
  failure comes from list forwarding, not from spoofing.
- Real origin: the lowest Received line is a Gmail server,
  mail-sor-f41.google.com (209.85.220.41). Gmail hides the sender's own
  IP, so I could not trace further back.
- Microsoft scored the message SCL 9 and delivered it to junk.

**Link**
- Both images link to hxxps://bit[.]ly/DGSFAHTRYSETAHSGFZBGNRTEHZRG
  with click tracking parameters (pid, uid, vid, ofid).
- The body has no readable text, so the lure itself is unknown.

**VirusTotal URL scan**
- 2 of 93 vendors flagged the short link. One said phishing, one said
  malicious and one more said suspicious. This was my own first
  submission, so there was no earlier community history.
- The redirect ends at an ad traffic quality script page on a Google
  domain, served from 172.217.72.132, status 200, empty body.
- No login form and no brand impersonation was observed. Vendor
  categories for the final page are benign.

 ![VirusTotal detections](../images/Screenshot_2026-11-12_111511.png)

![VirusTotal final URL](../images/Screenshot_2026-11-12_112838.png)

**Limits of this evidence**
- The email is from June 2023 and the scan is from November 2026, so the
  link may behave differently now.
- Scanners can be shown different content from real recipients.
- I saw the end of the redirect chain, not the hops between bit.ly and
  the final page.

## Benign explanations
Marketing email also uses shortened tracking links and image only
bodies. Mailing lists also break SPF and DMARC. For that reason I did
not judge the email on authentication results alone.

![VirusTotal Categories](../images/Screenshot_2026-11-12_112822.png)

## Verdict
Suspicious. The email shows several warning signs, namely a
meaningless sender name, a fake confirmation subject, an image only
body and a shortened link behind it. The URL scan did not confirm a
malicious destination, and the final page looks like ad tracking
infrastructure. I would not call it confirmed phishing without running
the full redirect chain in a sandbox.

## Severity
Low to medium. It rises if any recipient clicked or replied.

## Action
Block the sender and the short link, search the mail logs for other
recipients of the same message and ask anyone who clicked to report it.
If anyone entered credentials anywhere, reset their password and review
their recent sign ins.

## Next steps
Run the full redirect chain in a sandbox, not on my own machine, and
check whether the same sender or link appears in other samples.
