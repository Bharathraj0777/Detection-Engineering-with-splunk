# Detection Testing

## 1. Overview

This document describes the testing process used to validate the five Splunk detection rules developed in this project.

Each detection was tested against synthetic Windows and Sysmon-style telemetry imported into the Splunk `windows` index.

The purpose of testing was to verify that each detection:

* Executes successfully.
* Identifies the expected security behavior.
* Returns the expected events.
* Produces useful information for investigation.
* Can be documented and mapped to MITRE ATT&CK.

> **Note:** The telemetry used for testing is synthetic lab data created specifically for this project. It does not represent a real-world security incident.

---

## 2. Testing Environment

| Component          | Configuration                            |
| ------------------ | ---------------------------------------- |
| SIEM               | Splunk Enterprise                        |
| Index              | `windows`                                |
| Data               | Synthetic Windows/Sysmon-style telemetry |
| Detection Language | SPL                                      |
| Detection Count    | 5                                        |
| Testing Type       | Manual SPL query validation              |

---

## 3. Testing Methodology

Each detection followed the same testing process:

```text
Load Test Telemetry
       ↓
Run SPL Query
       ↓
Review Search Results
       ↓
Verify Expected Behavior
       ↓
Capture Evidence
       ↓
Document Result
```

The detection was considered successfully tested when the expected activity appeared in the Splunk search results.

---

# 4. Detection 1 — Brute Force Authentication

## Detection Information

* **Event ID:** `4625`
* **Event:** Failed Logon
* **MITRE ATT&CK:** T1110 — Brute Force

## Test Scenario

Multiple failed authentication attempts were generated from the same source IP against the same user within a 5-minute window.

### Test Values

| Field               | Value       |
| ------------------- | ----------- |
| Source IP           | `10.0.2.50` |
| Username            | `alice`     |
| Failed Attempts     | `4`         |
| Detection Threshold | `3`         |
| Time Window         | `5 minutes` |

## SPL Query

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time,src_ip,user
| where failed_attempts >= 3
```

## Expected Result

The detection should identify the repeated failed authentication attempts because 4 attempts exceeded the configured threshold of 3.

## Observed Result

The detection successfully identified:

```text
Source IP: 10.0.2.50
Username: alice
Failed Attempts: 4
```

## Test Status

**PASS — Detection triggered successfully**

## Evidence

Screenshot:

```text
screenshots/brute-force-detection.png
```

---

# 5. Detection 2 — Suspicious PowerShell

## Detection Information

* **Event ID:** `4104`
* **Event:** PowerShell Script Block Logging
* **MITRE ATT&CK:** T1059.001 — PowerShell

## Test Scenario

PowerShell Script Block Logging events containing suspicious indicators were included in the test telemetry.

### Test Indicators

* `EncodedCommand`
* `Invoke-WebRequest`

### Test User

```text
bob
```

## SPL Query

```spl
index=windows EventCode=4104
| search description="*EncodedCommand*" OR description="*Invoke-WebRequest*"
| stats count by _time,host,user,description
| sort - _time
```

## Expected Result

The detection should identify PowerShell events containing the configured indicators.

## Observed Result

The detection successfully identified PowerShell activity associated with:

```text
User: bob
Event ID: 4104
Indicators: EncodedCommand / Invoke-WebRequest
```

## Test Status

**PASS — Detection triggered successfully**

## Evidence

Screenshot:

```text
screenshots/suspicious-powershell.png
```

---

# 6. Detection 3 — Suspicious Process Creation

## Detection Information

* **Event ID:** `1`
* **Event:** Sysmon Process Creation
* **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter

## Test Scenario

The synthetic telemetry contained a process relationship involving Microsoft Word and a command interpreter.

### Test Process Relationship

```text
WINWORD.EXE → powershell.exe
```

The dataset also contains:

```text
powershell.exe → cmd.exe
```

## SPL Query

```spl
index=windows EventCode=1
| search description="*WINWORD.EXE*"
| search description="*powershell.exe*" OR description="*cmd.exe*"
| stats count by _time,host,user,description
| sort - _time
```

## Expected Result

The detection should identify the process creation event involving Microsoft Word and PowerShell or Command Prompt.

## Observed Result

The detection successfully identified the expected suspicious process relationship.

Example:

```text
Parent Process: WINWORD.EXE
Child Process: powershell.exe
Event ID: 1
```

## Test Status

**PASS — Detection triggered successfully**

## Evidence

Screenshot:

```text
screenshots/suspicious-process.png
```

---

# 7. Detection 4 — LSASS Access

## Detection Information

* **Event ID:** `10`
* **Event:** Sysmon Process Access
* **MITRE ATT&CK:** T1003.001 — LSASS Memory

## Test Scenario

The synthetic telemetry contained a process-access event involving `lsass.exe`.

### Test Activity

```text
Source Process: rundll32.exe
Target Process: lsass.exe
```

## SPL Query

```spl
index=windows EventCode=10
| search description="*lsass.exe*"
| stats count by _time,host,user,description
| sort - _time
```

## Expected Result

The detection should identify the Sysmon Process Access event involving LSASS.

## Observed Result

The detection successfully identified the LSASS access activity.

```text
Event ID: 10
Source Process: rundll32.exe
Target Process: lsass.exe
```

## Test Status

**PASS — Detection triggered successfully**

## Evidence

Screenshot:

```text
screenshots/lsass-access.png
```

---

# 8. Detection 5 — Suspicious Network Connection

## Detection Information

* **Event ID:** `3`
* **Event:** Sysmon Network Connection
* **MITRE ATT&CK:** T1071.001 — Web Protocols

## Test Scenario

The synthetic telemetry contained an outbound network connection initiated by PowerShell.

### Test Activity

```text
Process: powershell.exe
Destination: 203.0.113.50
Destination Port: 443
```

> `203.0.113.50` is a documentation/test IP address used in the synthetic dataset.

## SPL Query

```spl
index=windows EventCode=3
| search description="*powershell.exe*"
| stats count by _time,host,user,description
| sort - _time
```

## Expected Result

The detection should identify the PowerShell network connection.

## Observed Result

The detection successfully identified the network connection involving PowerShell.

```text
Process: powershell.exe
Destination: 203.0.113.50
Port: 443
Event ID: 3
```

## Test Status

**PASS — Detection triggered successfully**

## Evidence

Screenshot:

```text
screenshots/suspicious-network.png
```

---

# 9. Testing Summary

All five detection rules were manually tested against the synthetic telemetry.

| # | Detection                     | Event ID | MITRE ATT&CK | Result |
| - | ----------------------------- | -------: | ------------ | ------ |
| 1 | Brute Force Authentication    |     4625 | T1110        | PASS   |
| 2 | Suspicious PowerShell         |     4104 | T1059.001    | PASS   |
| 3 | Suspicious Process Creation   |        1 | T1059        | PASS   |
| 4 | LSASS Access                  |       10 | T1003.001    | PASS   |
| 5 | Suspicious Network Connection |        3 | T1071.001    | PASS   |

---

# 10. Evidence Collection

Screenshots were captured from Splunk after each detection returned the expected result.

The evidence files are stored in:

```text
screenshots/
```

Current evidence:

```text
screenshots/
├── brute-force-detection.png
├── suspicious-powershell.png
├── suspicious-process.png
├── lsass-access.png
└── suspicious-network.png
```

---

# 11. Testing Limitations

The testing was performed using synthetic telemetry rather than production security logs.

Therefore:

* The test environment does not represent a production SOC.
* The detection thresholds are demonstration values.
* The results validate the SPL logic against the supplied test cases.
* Successful detection does not prove that the rules would detect every real-world attack.
* Additional testing with diverse datasets would be required before production deployment.

---

# 12. Final Testing Status

**Total Detections Tested:** 5

**Successful Tests:** 5

**Failed Tests:** 0

**Overall Test Status:** PASS

All five detection rules successfully identified their intended test scenarios.
