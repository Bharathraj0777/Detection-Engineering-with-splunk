# Suspicious PowerShell Detection

## 1. Objective

Detect potentially suspicious PowerShell activity that may indicate command execution, script execution, or other malicious behavior.

The detection focuses on PowerShell Script Block Logging events containing indicators such as encoded commands and web-request activity.

---

## 2. Data Source

* **SIEM:** Splunk Enterprise
* **Log Source:** Windows PowerShell logs
* **Index:** `windows`
* **Event ID:** `4104`
* **Event Description:** PowerShell Script Block Logging
* **Telemetry Type:** Synthetic lab telemetry created for this project

> **Note:** The dataset used in this project is synthetic lab telemetry created for detection-engineering testing. It does not represent a real-world incident.

---

## 3. Detection Logic

The detection searches for PowerShell Script Block Logging events containing suspicious activity indicators.

The current detection looks for:

* `EncodedCommand`
* `Invoke-WebRequest`

These indicators can be associated with PowerShell activity that requires further investigation.

---

## 4. SPL Detection Query

```spl
index=windows EventCode=4104
| search description="*EncodedCommand*" OR description="*Invoke-WebRequest*"
| stats count by _time,host,user,description
| sort - _time
```

---

## 5. Query Explanation

### `index=windows`

Searches the Windows telemetry stored in the Splunk `windows` index.

### `EventCode=4104`

Filters for PowerShell Script Block Logging events.

### `description="*EncodedCommand*"`

Searches for PowerShell activity containing an encoded command indicator.

### `description="*Invoke-WebRequest*"`

Searches for PowerShell web-request activity.

### `stats count`

Counts matching events and groups them by time, host, user, and description.

---

## 6. MITRE ATT&CK Mapping

### T1059.001 — PowerShell

**Tactic:** Execution

PowerShell is a legitimate Windows administration and automation tool, but it can also be abused to execute commands and scripts.

Therefore, suspicious PowerShell activity should be investigated in context rather than automatically treated as malicious.

---

## 7. Test Scenario

### Scenario

A user generates PowerShell Script Block Logging events containing suspicious PowerShell indicators.

### Test Data

* **Username:** `bob`
* **Event ID:** `4104`
* **Indicators:** `EncodedCommand`, `Invoke-WebRequest`

The synthetic dataset contains PowerShell events designed to test the detection.

---

## 8. Detection Result

**Status: Tested Successfully**

The detection successfully identified PowerShell Script Block Logging events containing the configured suspicious indicators.

### Observed Activity

| Field     | Result                                 |
| --------- | -------------------------------------- |
| Username  | `bob`                                  |
| Event ID  | `4104`                                 |
| Indicator | `EncodedCommand` / `Invoke-WebRequest` |
| Detection | Triggered                              |

---

## 9. Investigation

When this detection generates an alert, a SOC analyst should investigate:

* Username
* Hostname
* PowerShell command or script content
* Parent process
* Child processes
* Destination IP/domain
* Command-line arguments
* Whether encoded commands were used
* Whether the activity was expected administrative activity
* Related authentication and process events

The analyst should correlate the PowerShell event with other available telemetry before determining whether the activity is malicious.

---

## 10. False Positive Considerations

PowerShell is commonly used for legitimate administrative tasks.

Possible legitimate activity includes:

* System administration
* Software deployment
* IT automation
* Monitoring scripts
* Security tools
* Configuration management

Therefore, PowerShell activity alone should not automatically be classified as malicious.

---

## 11. Detection Tuning

Potential tuning approaches include:

* Excluding known administrative scripts where appropriate.
* Allowlisting approved automation accounts.
* Correlating PowerShell events with process creation events.
* Correlating with network connections.
* Adding additional suspicious command indicators.
* Establishing a baseline of normal PowerShell activity.

---

## 12. Evidence

### Splunk Detection Result

![Suspicious PowerShell Detection](Screenshots/suspicious-powershell.png)
screen shot is provided in this path Screenshots/suspicious-powershell.png  for this repository

---

## 13. Detection Workflow

```text
PowerShell Activity
        ↓
EventCode 4104
        ↓
Splunk Index
    "windows"
        ↓
Search for suspicious indicators
        ↓
Detection Triggered
        ↓
SOC Investigation
        ↓
MITRE ATT&CK T1059.001
        ↓
Tuning / Validation
```

---

## 14. Detection Engineering Summary

This detection demonstrates:

* PowerShell telemetry analysis
* SPL filtering
* Suspicious indicator detection
* MITRE ATT&CK mapping
* SOC investigation workflow
* False-positive analysis
* Detection tuning

---

## 15. Status

**Detection:** Completed
**Testing:** Successful
**MITRE Mapping:** Completed
**Documentation:** Completed
