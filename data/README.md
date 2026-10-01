# Lab Data

## 1. Overview

This directory contains the data used for the Splunk Detection Engineering Lab.

The project uses synthetic Windows and Sysmon-style security telemetry to test and validate the detection rules.

The data is designed specifically for cybersecurity learning, detection engineering, and SIEM testing.

---

## 2. Data Source

The dataset contains simulated security events representing common Windows security behaviors.

The telemetry was imported into Splunk using the following index:

```text
windows
```

---

## 3. Dataset

The main dataset contains simulated events for the following detection scenarios:

| Detection                     | EventCode | Description                      |
| ----------------------------- | --------: | -------------------------------- |
| Brute Force Authentication    |      4625 | Multiple failed logon attempts   |
| Successful Logon              |      4624 | Successful authentication        |
| Suspicious PowerShell         |      4104 | Suspicious PowerShell activity   |
| Suspicious Process Creation   |         1 | Suspicious process relationships |
| LSASS Access                  |        10 | Process access involving LSASS   |
| Suspicious Network Connection |         3 | PowerShell network activity      |

---

## 4. Data Fields

The dataset contains fields such as:

| Field             | Description                       |
| ----------------- | --------------------------------- |
| `_time`           | Event timestamp                   |
| `EventCode`       | Windows/Sysmon event identifier   |
| `source`          | Event source                      |
| `host`            | Host associated with the event    |
| `src_ip`          | Source IP address                 |
| `user`            | User associated with the event    |
| `event_type`      | Type of security event            |
| `description`     | Event description                 |
| `mitre_technique` | Associated MITRE ATT&CK technique |

---

## 5. Detection Scenarios Included

### Brute Force

The dataset contains multiple failed authentication attempts from the same source IP against the same user.

Example:

```text
Source IP: 10.0.2.50
User: alice
EventCode: 4625
```

This is used to test the **T1110 — Brute Force** detection.

---

### Suspicious PowerShell

The dataset contains PowerShell Script Block Logging events containing indicators such as:

```text
EncodedCommand
Invoke-WebRequest
```

This is used to test **T1059.001 — PowerShell**.

---

### Suspicious Process Creation

The dataset contains simulated process relationships involving:

```text
WINWORD.EXE → powershell.exe
WINWORD.EXE → cmd.exe
```

This is used to test command and scripting interpreter detections.

---

### LSASS Access

The dataset contains a simulated process access event involving:

```text
rundll32.exe → lsass.exe
```

This is used to test **T1003.001 — LSASS Memory** detection logic.

---

### Suspicious Network Connection

The dataset contains a simulated PowerShell network connection:

```text
powershell.exe → 203.0.113.50:443
```

This is used to test suspicious network activity detection.

`203.0.113.50` is used as a documentation/test IP address.

---

## 6. Synthetic Data Notice

**This dataset is synthetic and is not real incident data.**

The events were created for the purpose of:

* SIEM testing
* Detection engineering
* SPL development
* MITRE ATT&CK mapping
* SOC investigation practice
* Dashboard testing

The dataset should not be interpreted as evidence of a real cyberattack.

---

## 7. Data Usage

The data was imported into Splunk and used to:

1. Create detection rules.
2. Test SPL queries.
3. Validate detection results.
4. Capture detection screenshots.
5. Map detections to MITRE ATT&CK.
6. Test dashboard panels.
7. Document the detection engineering process.

---

## 8. Data Limitations

The dataset is intentionally small and simplified.

It does not represent the volume or complexity of a production SOC environment.

Limitations include:

* Limited number of events
* Synthetic timestamps
* Simulated attack behaviors
* Limited host information
* Limited process metadata
* No real endpoint telemetry
* No threat intelligence enrichment
* No production-scale event volume

---

## 9. Future Data Sources

The project can later be expanded using real lab telemetry from:

* Windows Event Logs
* Sysmon
* Splunk Universal Forwarder
* Wazuh
* Suricata
* Linux audit logs
* Cloud logs
* Authentication logs
* Endpoint Detection and Response telemetry

This would allow the detections to be tested against more realistic SOC data.

---

## 10. Data Status

| Item                 | Status           |
| -------------------- | ---------------- |
| Synthetic Dataset    | Available        |
| Splunk Import        | Completed        |
| Detection Testing    | Completed        |
| MITRE Mapping        | Completed        |
| Dashboard Testing    | Planned/Optional |
| Production Telemetry | Not Implemented  |

**Data Documentation Status: Complete**

