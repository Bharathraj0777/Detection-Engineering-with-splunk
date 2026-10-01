# LSASS Access Detection

## 1. Objective

Detect suspicious process access to the Windows Local Security Authority Subsystem Service (`lsass.exe`).

LSASS is a Windows process that handles important authentication and security operations. Unauthorized access to LSASS can be associated with credential-access techniques and therefore requires investigation.

---

## 2. Data Source

* **SIEM:** Splunk Enterprise
* **Log Source:** Sysmon
* **Index:** `windows`
* **Event ID:** `10`
* **Event Description:** Process Access
* **Telemetry Type:** Synthetic lab telemetry created for this project

> **Note:** The dataset used in this project is synthetic lab telemetry created for detection-engineering testing. It does not represent a real-world incident.

---

## 3. Detection Logic

The detection searches for Sysmon Process Access events involving `lsass.exe`.

The objective is to identify processes that attempt to access the LSASS process and generate the activity for SOC investigation.

### Detection Condition

```text
Sysmon Event ID 10
        +
lsass.exe involved
        ↓
Potentially suspicious LSASS access
```

---

## 4. SPL Detection Query

```spl
index=windows EventCode=10
| search description="*lsass.exe*"
| stats count by _time,host,user,description
| sort - _time
```

---

## 5. Query Explanation

### `index=windows`

Searches the Windows telemetry stored in the Splunk `windows` index.

### `EventCode=10`

Filters for Sysmon Process Access events.

### `description="*lsass.exe*"`

Searches for events involving the LSASS process.

### `stats count`

Counts matching events and groups them by:

* Time
* Host
* User
* Description

### `sort - _time`

Displays the newest events first.

---

## 6. MITRE ATT&CK Mapping

### T1003.001 — LSASS Memory

**Tactic:** Credential Access

Unauthorized access to LSASS can be associated with attempts to obtain credential material from LSASS memory.

This detection identifies the process-access activity for further investigation. It does not by itself prove that credential dumping occurred.

---

## 7. Test Scenario

### Scenario

A process attempts to access the LSASS process.

The synthetic dataset contains a Sysmon Process Access event designed to test this detection.

### Test Data

Example activity:

```text
Source Process: rundll32.exe
Target Process: lsass.exe
Event ID: 10
```

The detection should identify this event.

---

## 8. Detection Result

**Status: Tested Successfully**

The detection successfully identified a Sysmon Process Access event involving `lsass.exe`.

### Observed Activity

| Field          | Result         |
| -------------- | -------------- |
| Event ID       | `10`           |
| Source Process | `rundll32.exe` |
| Target Process | `lsass.exe`    |
| Event Type     | Process Access |
| Detection      | Triggered      |

The event requires further investigation to determine whether the LSASS access was legitimate or suspicious.

---

## 9. Investigation

When this detection generates an alert, a SOC analyst should investigate:

### Process Investigation

* Source process
* Target process
* Process ID
* Parent process
* Command-line arguments
* Process executable path
* Process user

### Host Investigation

* Hostname
* Recent logon activity
* Other suspicious process executions
* PowerShell activity
* Network connections
* Other security events

### Correlation

Look for related activity such as:

```text
LSASS Access
     ↓
Suspicious Process Creation
     ↓
PowerShell Activity
     ↓
Network Connection
```

Correlation with other telemetry can provide additional context.

---

## 10. False Positive Considerations

Not every LSASS access event represents malicious activity.

Possible legitimate causes include:

* Security software
* Endpoint monitoring tools
* Antivirus/EDR products
* System processes
* Administrative tools
* Operating-system activity

Therefore, the source process and surrounding activity should be investigated before classifying an alert as malicious.

---

## 11. Detection Tuning

Potential tuning approaches include:

* Identify known legitimate security tools accessing LSASS.
* Allowlist approved security processes where appropriate.
* Monitor unusual source processes.
* Add process-path analysis.
* Add command-line analysis.
* Correlate with other credential-access indicators.
* Establish a baseline of legitimate LSASS access.

### Example

Instead of alerting on every LSASS access event, a more mature detection could focus on:

```text
Unusual Process
      +
LSASS Access
      +
Suspicious Command Line
```

This can help reduce false positives.

---

## 12. Evidence

### Splunk Detection Result

![LSASS Access Detection](../screenshots/lsass-access.png)

The screenshot should show the Splunk search result containing the LSASS access event.

---

## 13. Detection Workflow

```text
Sysmon Process Access
          ↓
      EventCode 10
          ↓
    Splunk Index
      "windows"
          ↓
    Search for
     lsass.exe
          ↓
 Detection Triggered
          ↓
   SOC Investigation
          ↓
MITRE ATT&CK T1003.001
          ↓
 Correlation & Tuning
```

---

## 14. Detection Engineering Summary

This detection demonstrates:

* Sysmon Process Access analysis
* LSASS monitoring
* Credential-access detection
* SPL filtering
* MITRE ATT&CK mapping
* SOC investigation methodology
* False-positive analysis
* Detection tuning
* Event correlation

---

## 15. Status

**Detection:** Completed
**Testing:** Successful
**MITRE Mapping:** Completed
**Documentation:** Completed
