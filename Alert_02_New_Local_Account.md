# Alert 02. New local account added to Administrators

| | |
|---|---|
| **Data source** | Windows Security log from my own PC, ingested into Splunk Enterprise |
| **Environment** | Single Windows 10 machine, local accounts only, no domain |
| **Tactic** | Persistence |
| **MITRE ATT&CK** | T1136.001 Create Account: Local Account. T1098 Account Manipulation |
| **Related** | T1069.001 Permission Groups Discovery (the 4799 event, see timeline) |
| **Severity** | High if unexplained. Low in this lab because I caused it |
| **Verdict** | True positive (lab, self-generated) |

---

## 1. Summary

A local account called `svc_backup` was created and added to the built in Administrators group 46 seconds later. Both actions came from the same interactive desktop session, owned by the local account `User`. The name was chosen to look like a service account, which is a common way for an attacker to blend in.

I then repeated the promotion with an existing account (`testuser`) and found that no account creation event exists in that case, so a rule that only watches for new accounts would miss it. Section 7 covers this gap and the detection I would use instead.

---

## 2. Why this matters

After an attacker gets in, a stolen password is a weak foothold. It can be reset, or the user can log out. A new local admin account is a second way back in that survives a password reset on the original account. One event alone proves little, because accounts are created and groups are changed all the time. The alert is the combination: **a new account that becomes an administrator within minutes.**

Windows logs both actions by default on a normal PC, so no audit policy changes were needed.

| Event | Meaning |
|---|---|
| 4720 | A user account was created |
| 4732 | A member was added to a security-enabled local group |
| 4726 | A user account was deleted |

---

## 3. What I did (the simulated attack)

From an administrator Command Prompt:

```
net user svc_backup * /add
net localgroup administrators svc_backup /add
net localgroup administrators
```

The asterisk makes Windows ask for the password, so it never appears in the command history or the logs.

Cleanup the next day:

```
net user svc_backup /delete
```

---

## 4. Investigation

### 4.1 Finding the events

```
index=main source="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| sort _time
| table _time, EventCode, Message
```

This returned 3 events: one 4720 and two 4732. Two 4732 events for one account was the first surprise, and working out which one mattered was part of the job.

[![4720 and 4732 search results in Splunk](images/Screenshot%202026-11-10%20130326%281%29.png)](images/Screenshot%202026-11-10%20130326%281%29.png)

### 4.2 Linking the events by SID

The 4732 event shows the member's `Account Name` as `-`. The name `svc_backup` does not appear in it at all. For local accounts the event identifies the member only by SID, so matching on the name would have found nothing.

| Event | Field | Value |
|---|---|---|
| 4720 | New Account, Security ID | ...-1003 |
| 4732 | Member, Security ID | ...-1003 |

The two SIDs match, which proves that the account created in the 4720 is the same account added to the group in the 4732. Only the final part of each SID is shown here. The machine specific prefix is removed.

[![Both 4732 events showing member SID 1003](images/Screenshot%202026-11-10%20130414%281%29.png)](images/Screenshot%202026-11-10%20130414%281%29.png)

### 4.3 Telling the two 4732 events apart

| Time | Group SID | Group name | Meaning |
|---|---|---|---|
| 19:58:40.876 | S-1-5-32-545 | Users | Default group Windows adds every new account to. Not an alert |
| 19:59:26.447 | S-1-5-32-544 | Administrators | The alert |

I identified the dangerous event by the **group SID**, not by the group name. The name can be localised or renamed, while the SID for Administrators is the same on every Windows machine. A detection built on the SID is harder to dodge.

[![4732 event for the Administrators group at 19:59:26](images/Screenshot%202026-11-10%20130437%281%29.png)](images/Screenshot%202026-11-10%20130437%281%29.png)

### 4.4 Who did it, and what else did the session do

Subject of all events: local account `User` (RID 1001), Logon ID `0x107C4C85`.

Searching that Logon ID with no other filter returned **1,697 events**. The reason is the key finding here. In Alert 1 the Logon ID belonged to a short network connection with almost nothing in it. This one belongs to the **interactive desktop login**, which stayed open from the moment I signed in to Windows until the next day. It holds everything the desktop session did. The same Logon ID also appears on a 4732 at 13:16 the next day, so the session was open for at least 17 hours.

Most of those events are background noise (4799 and 5379). I narrowed the search to the minutes around the account creation:

```
index=main source="WinEventLog:Security" Logon_ID="0x107C4C85" earliest="11/09/2026:19:57:00" latest="11/09/2026:20:00:30"
| stats count by EventCode
```

Event types in that window: **4720, 4722, 4724, 4728, 4732, 4738, 4799.**

[![Event count by EventCode in the time window](images/Screenshot%202026-11-10%20185217.png)](images/Screenshot%202026-11-10%20185217.png)

```
index=main source="WinEventLog:Security" Logon_ID="0x107C4C85" earliest="11/09/2026:19:57:00" latest="11/09/2026:20:00:30"
| sort _time
| table _time, EventCode, Message
```

---

## 5. Timeline

All times are 9 November 2026 unless stated.

| Time | Event | What happened |
|---|---|---|
| not captured | 4728 | `svc_backup` added to the default global group "None" (automatic). The timestamp was cut off in my export, so I make no claim about its exact time |
| 19:58:40.808 | 4720 | `svc_backup` created. Starts disabled with "Password Not Required" set |
| 19:58:40.871 | 4724 | Password set on the account |
| 19:58:40.871 | 4738 | Account changed. "Password Not Required" switched off |
| 19:58:40.871 | 4722 | Account enabled |
| 19:58:40.876 | 4732 | Added to Users (automatic) |
| **19:59:26.447** | **4732** | **Added to Administrators. 45.6 seconds after creation** |
| 19:59:39.787 | 4799 | Administrators group membership listed by `net1.exe` |
| 10 Nov 13:13:29 | 4726 | `svc_backup` deleted |

[![4726 event showing svc_backup deleted at 13:13:29](images/Screenshot%202026-11-10%20131624%281%29.png)](images/Screenshot%202026-11-10%20131624%281%29.png)

Notes on the timeline:

1. The 4720 to 4722 sequence took about 63 milliseconds. The account is created disabled with no password required, and Windows immediately sets a password, clears the flag and enables it. This is how `net user` builds an account. It looks alarming on first read but is normal, so I do not count it as suspicious.

   [![4720 attributes showing Password Not Required and the UAC change](images/Screenshot%202026-11-10%20130350.png)](images/Screenshot%202026-11-10%20130350.png)

2. The 4799 at 19:59:39 is my own check, `net localgroup administrators`, run 13 seconds after the promotion. The process name `net1.exe` in the event confirms it. In a real case this would be the attacker confirming that the promotion worked, so the process name and the time gap would be worth recording.
3. The account existed for about 17 hours before I deleted it. That is because I cleaned up the next day, so the gap says nothing about attacker behaviour.

---

## 6. Assessment

**First thought.** Persistence. A new account with a service style name, promoted to admin within a minute, from an interactive session.

**What else it could have been.**
- An IT administrator onboarding a user or creating a break glass account.
- Backup or management software that creates its own local admin account during install.
- A technician working directly at the machine.

**The check that separates them.** Whether anyone can name the person and the reason. A legitimate change has a ticket, a requester and an owner.

**Why the source matters.** The Logon ID is an interactive console session, so the account was created by someone at this machine, not remotely. The question in a real case then becomes whether that was the real `User` or someone using an unlocked session. The logs cannot answer that on their own.

**Verdict.** True positive in this lab because I generated it. In a real environment I would treat it as malicious until the creator confirmed it.

**Severity.** High if unexplained. An administrator account gives full control of the machine. I would lower it only if the creator is a known admin and a ticket exists.

**Action.**
1. Ask the owner of the `User` account whether they did it, and check the ticketing system.
2. Search for logons by `svc_backup` (4624) to see whether the account was ever used.
3. If nothing explains it, escalate and **disable the account instead of deleting it**, which keeps the evidence.
4. If I was wrong and it was legitimate, the cost is that I disturbed an administrator doing normal work. That is a cheap mistake compared with leaving a real backdoor in place.

---

## 7. Detection gap I tested

I added an existing account to Administrators without creating a new one:

```
net localgroup administrators testuser /add
```

Result: a 4732 at 13:16:45 on 10 November, same Subject and same Logon ID, Group `Administrators` (S-1-5-32-544), Member SID ending in 1002. I confirmed that 1002 is `testuser` with:

```
powershell -command "Get-LocalUser | Select Name, SID"
```

[![Three 4732 events including testuser added at 13:16:45](images/Screenshot%202026-11-10%20131917%281%29.png)](images/Screenshot%202026-11-10%20131917%281%29.png)

There is **no 4720 anywhere near this event**, because no account was created. A rule that only looks for new accounts would miss it completely.

I removed `testuser` from Administrators afterwards and confirmed it with `net localgroup administrators`, which listed only the built in Administrator and User.

### Detection I would use

The simple rule, which covers both cases:

```
index=main source="WinEventLog:Security" EventCode=4732 "S-1-5-32-544"
```

Any member added to Administrators gets reviewed, whether the account is new or old.

A correlation version, which raises the priority when the account is also new. **This is a draft. I have not run it in the lab yet, so it needs testing before I rely on it.**

```
index=main source="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| rex field=Message "(?s)(?:New Account|Member):\s+Security ID:\s+(?<target_sid>S-1-5-21-[\d-]+)"
| rex field=Message "(?s)Group:\s+Security ID:\s+(?<group_sid>S-1-5-[\d-]+)"
| eval created=if(EventCode=4720,_time,null())
| eval promoted=if(EventCode=4732 AND group_sid="S-1-5-32-544",_time,null())
| stats min(created) as created min(promoted) as promoted by target_sid
| where isnotnull(created) AND isnotnull(promoted) AND (promoted-created)<3600
```

---

## 8. Limitations

- **This is a lab.** I caused every event, so the "True positive" verdict is trivial. The value is in the method, not the verdict.
- **Process creation auditing (4688) is off by default.** I saw no 4688, 4672 or 4648 in the window, but that does **not** prove nothing else ran. The correct statement is "no further events were logged", never "nothing else happened".
- **One machine, local accounts only.** In a domain the equivalent events would be logged on domain controllers with different event codes for domain accounts, and the investigation would look different.
- **The session was my own and stayed open.** In a real intrusion the Logon ID would more likely be a short remote session, which would make the pivot on Logon ID much cleaner.
- **The detection query in section 7 is untested.**

---

## 9. Where I got stuck

1. **The member name was missing.** The 4732 event showed `-` in place of `svc_backup`. I had to match the two events by SID instead.
2. **Two 4732 events for one account.** I had to work out that the first was the automatic Users group and only the second was the alert.
3. **My first Logon ID search proved nothing.** I left the `EventCode=4720 OR EventCode=4732` filter in the search, so it could only ever return the same 3 events I already knew about. Removing the filter exposed the real session, with 1,697 events.

   [![First Logon ID search that only returned the same 3 events](images/Screenshot%202026-11-10%20131158%281%29.png)](images/Screenshot%202026-11-10%20131158%281%29.png)

4. **The Logon ID was not what I expected.** I assumed it would be a short session like in Alert 1. It turned out to be my whole desktop login, so I had to narrow by time window.
5. **`Get-LocalUser` failed in Command Prompt.** It is a PowerShell command. Running it through `powershell -command "..."` fixed it.
