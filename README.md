# Defender-XDR-Keyboard-Attack
Investigation on a Defender alert on my VM device. 

# Microsoft Defender XDR Incident Investigation
## Distinguishing Cyber Range Activity from a Potential Compromise

## Overview

While working in a cybersecurity training environment, Microsoft Defender XDR generated a high-severity incident involving my Windows lab VM, `christianmc-lab`.

The incident was titled:

> **"Hands-on keyboard attack was launched from a compromised account (attack disruption)"**

The incident contained detections associated with several security tactics, including:

- Initial Access
- Persistence
- Defense Evasion
- Credential Access
- Lateral Movement
- Suspicious Activity

Because the incident appeared to involve my lab VM and the `CMAdmin` account, my initial concern was that the VM may have been successfully compromised.

Rather than assuming the high-severity incident represented a confirmed intrusion, I used Microsoft Defender Advanced Hunting to investigate the underlying authentication, process, and registry telemetry.

As the investigation progressed, multiple detections associated with my VM were traced back to activity that I had intentionally performed during cybersecurity labs or to explainable application behavior.

Most importantly, my review of the available authentication telemetry did not identify an unexplained successful remote authentication to the VM.

Based on the evidence reviewed during the investigation, I found **no evidence establishing a successful compromise of `christianmc-lab`**.

---

# Investigation Objectives

The investigation focused on answering several questions:

1. Was `christianmc-lab` actually compromised?
2. Was the `CMAdmin` account successfully accessed by an unauthorized user?
3. Did an attacker establish persistence?
4. Were the Defender alerts caused by malicious behavior or legitimate cyber-range activity?
5. Did Defender correlate activity from my lab environment with a larger incident involving other entities?
6. Could the evidence support or reject my original compromise hypothesis?

---

# Environment

**Platform:** Microsoft Defender XDR / Microsoft Defender for Endpoint  
**Endpoint:** Windows lab VM  
**Device:** `christianmc-lab`  
**Primary Account Investigated:** `CMAdmin`  
**Investigation Method:** Microsoft Defender Advanced Hunting  
**Query Language:** Kusto Query Language (KQL)  
**Environment:** Authorized cybersecurity training / cyber range environment

Advanced Hunting tables used during the investigation included:

- `DeviceLogonEvents`
- `DeviceProcessEvents`
- `DeviceRegistryEvents`
- `DeviceEvents`

---

# Initial Alert

Microsoft Defender XDR associated `christianmc-lab` with a high-severity incident titled:

> **Hands-on keyboard attack was launched from a compromised account (attack disruption)**

The broader incident referenced activity associated with tactics including:

- Initial Access
- Persistence
- Defense Evasion
- Credential Access
- Lateral Movement

At first, the incident appeared to indicate that my VM or account might have been involved in an actual compromise.

## Screenshot 1 - Defender XDR Incident

<img width="468" height="229" alt="image" src="https://github.com/user-attachments/assets/7b733e1f-0ba2-45d2-849a-2d70166dfab7" />

### Initial Assessment

Because the incident referenced a compromised account and lateral movement, my initial working hypothesis was:

> **An attacker may have obtained access to the `CMAdmin` account and successfully accessed `christianmc-lab`.**

I did not want to assume that the presence of a high-severity alert automatically proved a compromise, so I began examining the individual alerts and underlying telemetry.

---

# Associated Endpoint Alerts

Several additional alerts were associated with `christianmc-lab`.

These included detections related to:

- Registry persistence
- Scheduled tasks
- Defense evasion
- Autorun / Run-key behavior

## Screenshot 2 - Associated Defender Alerts

<img width="468" height="101" alt="image" src="https://github.com/user-attachments/assets/4cda408f-ae2b-4713-ac24-013b3cb54b2c" />

At this point, the evidence appeared concerning because multiple detections resembled techniques commonly investigated during an intrusion.

However, because this VM was specifically being used for cybersecurity training, I needed to determine whether these detections represented attacker activity or my own lab activity.

--- 

# Initial Incident Response - Device Isolation

After reviewing the initial high-severity Defender XDR incident, I treated `christianmc-lab` as potentially compromised until I could determine what had actually occurred.

Because the incident referenced activity involving credential access, persistence, and lateral movement, I decided to take a precautionary containment action before continuing the investigation.

Using Microsoft Defender XDR, I **isolated `christianmc-lab` from the network**.

The purpose of this action was to contain the endpoint while I investigated the authentication, process, and registry telemetry associated with the incident.

## Screenshot 3 - Device Isolation

<img width="468" height="201" alt="image" src="https://github.com/user-attachments/assets/957f7292-f515-4e0c-8cdb-f97842d42b6b" />

### Incident Response Decision

At this point in the investigation, I had not yet determined whether the activity represented:

- A successful compromise
- Attempted credential access
- Persistence established by an attacker
- Lateral movement involving the VM
- Legitimate activity generated by my cybersecurity labs
- A combination of legitimate lab activity and activity correlated from the broader Defender XDR incident

Because successful compromise had not yet been ruled out, I chose to **contain first and investigate further**.

After isolating the endpoint, I continued the investigation using Microsoft Defender Advanced Hunting to test my initial compromise hypothesis against the available telemetry.

This added an important incident-response component to the investigation:

**Detection → Triage → Containment → Investigation → Analysis → Final Assessment**

The later investigation ultimately found no evidence in the telemetry I reviewed that established a successful compromise of `christianmc-lab`. However, isolation was an appropriate precaution based on the information available to me at the beginning of the investigation.

---

# Hypothesis 1 - Compromised Credentials

One of my first theories was that the `CMAdmin` account might have been compromised.

The broader incident included authentication-related activity that made credential attacks such as password guessing or password spraying worth investigating.

If an attacker had successfully obtained valid credentials, I expected that authentication telemetry might contain an unauthorized successful remote authentication.

I therefore began by reviewing authentication activity associated with `christianmc-lab`.

---

# Authentication Investigation

## Query 1 - Authentication Activity for christianmc-lab

```kusto
DeviceLogonEvents
| where DeviceName contains "christianmc-lab"
| where Timestamp between (
    datetime(2026-10-25 00:00:00) ..
    datetime(2026-10-28 00:00:00)
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    LogonType,
    AccountName,
    AccountDomain,
    RemoteIP,
    RemoteDeviceName,
    Protocol,
    FailureReason,
    IsLocalAdmin,
    LogonId
| order by Timestamp asc
```

## Screenshot 4 - VM Authentication Timeline

<img width="468" height="152" alt="image" src="https://github.com/user-attachments/assets/8e0cb9b8-a3a5-40dc-8caf-185c17852654" />

### Finding

I reviewed the authentication activity and compared the successful logons against the times when I was personally accessing the cyber range.

The successful remote sessions identified during the investigation corresponded to periods when I was legitimately using the VM.

The reviewed results did not reveal an unexplained successful remote authentication to `christianmc-lab`.

### Impact on Hypothesis

This weakened my initial hypothesis that an attacker had successfully authenticated directly to the VM.

However, additional investigation was required before reaching a final conclusion.

---

# CMAdmin Authentication Investigation

I next narrowed the authentication investigation specifically to the `CMAdmin` account.

The goal was to determine whether the account showed a successful authentication at a time or from a source that I could not explain.

## Query 2 - CMAdmin Authentication Timeline

```kusto
DeviceLogonEvents
| where DeviceName contains "christianmc-lab"
| where AccountName =~ "cmadmin"
| where Timestamp between (
    datetime(2026-10-25 00:00:00) ..
    datetime(2026-10-28 00:00:00)
)
| project
    Timestamp,
    ActionType,
    LogonType,
    AccountName,
    RemoteIP,
    RemoteDeviceName,
    Protocol,
    FailureReason,
    IsLocalAdmin,
    LogonId
| order by Timestamp asc
```

## Screenshot 5 - CMAdmin Authentication Activity

<img width="468" height="139" alt="image" src="https://github.com/user-attachments/assets/609e7e19-d897-40d2-86d4-8442609a4bc9" />

### Finding

The successful remote logons visible for `CMAdmin` aligned with periods when I was actively using the VM.

During the reviewed period, I did not identify an unexplained successful remote login associated with `CMAdmin`.

This became an important turning point in the investigation.

If the account had been successfully compromised through credential guessing, I expected to potentially find authentication activity that could not be accounted for.

The evidence reviewed did not provide that confirmation.

---

# Remote Authentication Source Analysis

I next grouped authentication activity by remote IP address.

The purpose of this analysis was to identify:

- Sources generating authentication activity
- Successful versus failed authentication attempts
- Accounts involved
- First and last observed activity
- Logon types
- Failure reasons

## Query 3 - Authentication Activity by Remote IP

```kusto
DeviceLogonEvents
| where DeviceName contains "christianmc-lab"
| where Timestamp between (
    datetime(2026-10-25 00:00:00) ..
    datetime(2026-10-28 00:00:00)
)
| where isnotempty(RemoteIP)
| summarize
    Attempts = count(),
    SuccessfulAttempts = countif(ActionType =~ "LogonSuccess"),
    FailedAttempts = countif(ActionType =~ "LogonFailed"),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Accounts = make_set(AccountName),
    Actions = make_set(ActionType),
    LogonTypes = make_set(LogonType),
    FailureReasons = make_set(FailureReason)
    by RemoteIP
| order by Attempts desc
```

## Screenshot 6 - Authentication Sources

<img width="468" height="136" alt="image" src="https://github.com/user-attachments/assets/51435cc8-b058-4aea-9107-9589a4247e26" />

### Finding

This query allowed the authentication history to be evaluated by source rather than examining individual events in isolation.

The authentication evidence reviewed during the investigation did not establish that an unknown source successfully authenticated to `christianmc-lab`.

Combined with the previous authentication queries, this further reduced confidence in the original compromised-account hypothesis.

---

# Hypothesis 2 - Attacker Persistence

Several Defender alerts suggested persistence-related activity.

One of the alerts involved scheduled-task behavior.

Scheduled tasks are important during security investigations because they can be abused to establish persistence or execute programs at predetermined times.

Initially, this alert appeared potentially related to the larger incident.

I therefore examined the underlying process telemetry.

---

# Scheduled Task Investigation

## Query 4 - LabUpdaterTask Activity

```kusto
DeviceProcessEvents
| where DeviceName contains "christianmc-lab"
| where ProcessCommandLine contains "LabUpdaterTask"
    or InitiatingProcessCommandLine contains "LabUpdaterTask"
| project
    Timestamp,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp asc
```

## Screenshot 7 - LabUpdaterTask Evidence

<img width="468" height="206" alt="image" src="https://github.com/user-attachments/assets/2b345196-a0a2-4a4b-ab72-2742840b2626" />

### Finding

The investigation revealed scheduled-task commands involving `LabUpdaterTask`.

The creation command was:

```cmd
schtasks /create /tn LabUpdaterTask /tr C:\Windows\System32\notepad.exe /sc daily /st 09:00 /f
```

The task was later removed using:

```cmd
schtasks /delete /tn LabUpdaterTask /f
```

I recognized both commands.

**I had intentionally executed these commands myself as part of a cybersecurity training lab.**

### Why This Was Important

This explained activity that initially looked like potential attacker persistence or defense evasion.

The security detection identified real behavior associated with a technique defenders should investigate.

However, in this environment, the context showed that the activity had been intentionally generated during an authorized lab exercise.

This demonstrated an important difference:

> **Detecting attacker-like behavior does not automatically prove that an attacker performed the behavior.**

---

# Registry Persistence Investigation

Another alert was associated with Windows autorun persistence behavior.

The detection referenced activity involving a Run key or similar autorun mechanism.

Because registry autorun locations can be abused for persistence, I initially treated the event as potentially suspicious.

I investigated the registry telemetry underlying the alert.

## Query 5 - Microsoft Edge Autorun Activity

```kusto
DeviceRegistryEvents
| where DeviceName contains "christianmc-lab"
| where RegistryValueName startswith "MicrosoftEdgeAutoLaunch_"
    or RegistryValueData contains "--win-session-start"
| project
    Timestamp,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp asc
```

## Screenshot 8 - Registry Persistence Investigation

<img width="468" height="231" alt="image" src="https://github.com/user-attachments/assets/d756d6a1-91f4-49a2-8739-6f2eeb9c2b43" />

### Finding

The registry value involved:

```text
MicrosoftEdgeAutoLaunch_...
```

The registry value pointed to:

```text
C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```

with arguments including:

```text
--no-startup-window --win-session-start
```

The initiating process was:

```text
msedge.exe
```

The underlying registry evidence provided important context for the behavior-based persistence detection.

Instead of an unknown executable or suspicious script being launched through the Run key, the evidence pointed to Microsoft Edge.

This event therefore did not, by itself, establish malicious persistence on the endpoint.

---

# Final Assessment

After reviewing authentication, process, registry, and alert telemetry for `christianmc-lab`, I found **no evidence establishing that the VM was successfully compromised**.

The investigation determined that several suspicious detections were attributable to known activity in my cybersecurity lab, including the creation and deletion of `LabUpdaterTask`. The investigated Run-key persistence detection was associated with Microsoft Edge auto-start behavior, and my authentication review did not reveal an unexplained successful remote login.

Although the initial Defender XDR incident appeared serious, the evidence supported a different conclusion: **legitimate attack-like activity from my cyber-range exercises contributed to the alerts associated with my VM rather than confirming a successful compromise.**

This investigation reinforced an important SOC lesson:

> **An alert is the beginning of an investigation, not proof of compromise. Follow the evidence, test the hypothesis, and be willing to change the conclusion.**
