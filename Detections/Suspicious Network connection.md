# Suspicious Network Connection Detection

## 1. Objective

Detect potentially suspicious outbound network connections initiated by PowerShell.

PowerShell is a legitimate Windows administration tool, but it can also communicate with external systems. Therefore, unusual PowerShell network connections can provide useful context during security investigations.

This detection identifies network connection events where PowerShell is involved and allows the activity to be investigated alongside other telemetry.

---

## 2. Data Source

* **SIEM:** Splunk Enterprise
* **Log Source:** Sysmon
* **Index:** `windows`
* **Event ID:** `3`
* **Event Description:** Network Connection
* **Telemetry Type:** Synthetic lab telemetry created for this project

> **Note:** The dataset used in this project is synthetic lab telemetry created for detection-engineering testing. It does not represent a real-world incident.

---

## 3. Detection Logic

The detection searches for Sysmon Network Connection events involving PowerShell.

### Detection Condition

```text id="3grqhl"
Sysmon Event ID 3
        +
PowerShell involved
        ↓
Potentially suspicious network activity
        ↓
SOC investigation
```

The detection does not automatically classify the connection as malicious. The destination, process, user, and surrounding activity must be investigated.

---

## 4. SPL Detection Query

```spl id="7sv6eg"
index=windows EventCode=3
| search description="*powershell.exe*"
| stats count by _time,host,user,description
| sort - _time
```

---

## 5. Query Explanation

### `index=windows`

Searches the Windows telemetry stored in the Splunk `windows` index.

### `EventCode=3`

Filters for Sysmon Network Connection events.

### `description="*powershell.exe*"`

Searches for network connections involving PowerShell.

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

### T1071.001 — Web Protocols

**Tactic:** Command and Control

PowerShell communicating over HTTP/HTTPS can be relevant to investigations involving command-and-control activity.

However, a network connection to port `443` alone does not prove malicious activity because HTTPS is widely used for legitimate communications.

The MITRE ATT&CK mapping should therefore be treated as investigative context rather than proof of malicious behavior.

---

## 7. Test Scenario

### Scenario

PowerShell establishes an outbound network connection.

The synthetic dataset contains a Sysmon network connection event designed to test this detection.

### Test Data

Example activity:

```text id="t7u5y1"
Process: powershell.exe
Destination: 203.0.113.50
Destination Port: 443
Event ID: 3
```

The detection should identify this event.

> `203.0.113.50` is a documentation/test IP address used in the synthetic dataset.

---

## 8. Detection Result

**Status: Tested Successfully**

The detection successfully identified a Sysmon Network Connection event involving PowerShell.

### Observed Activity

| Field            | Result             |
| ---------------- | ------------------ |
| Event ID         | `3`                |
| Process          | `powershell.exe`   |
| Destination      | `203.0.113.50`     |
| Destination Port | `443`              |
| Event Type       | Network Connection |
| Detection        | Triggered          |

The connection requires further investigation to determine whether it represents legitimate or suspicious activity.

---

## 9. Investigation

When this detection generates an alert, a SOC analyst should investigate:

### Network Investigation

* Destination IP address
* Destination domain, if available
* Destination port
* Protocol
* Connection time
* Frequency of connections
* Whether the destination is known or expected

### Process Investigation

* PowerShell process
* Parent process
* Command-line arguments
* PowerShell Script Block Logging
* Process creation events

### User Investigation

* Username
* Whether the user normally performs PowerShell network activity
* Whether the activity occurred during expected administrative work

### Correlation

Look for related events such as:

```text id="p1tqkf"
PowerShell Activity
       ↓
PowerShell Process Creation
       ↓
Network Connection
       ↓
Possible Suspicious Activity
```

Correlation with other telemetry provides stronger investigative context.

---

## 10. False Positive Considerations

PowerShell network connections can be completely legitimate.

Possible legitimate causes include:

* Software installation
* System administration
* API communication
* Automation scripts
* Configuration management
* Security tools
* Software updates
* Monitoring systems

Therefore, the destination and PowerShell command should be examined before classifying the activity as malicious.

---

## 11. Detection Tuning

Potential tuning approaches include:

* Establish a baseline of normal PowerShell network activity.
* Identify approved administrative scripts.
* Identify known legitimate destinations.
* Correlate network activity with PowerShell Script Block Logging.
* Correlate with suspicious process creation.
* Investigate unusual external destinations.
* Add command-line context.
* Add frequency-based thresholds.

### Example of stronger correlation

Instead of alerting only on:

```text id="2h3ncb"
PowerShell → Network Connection
```

a stronger investigation could correlate:

```text id="3xwq9b"
Office Application
      ↓
PowerShell
      ↓
Encoded Command
      ↓
External Network Connection
```

This provides significantly more context for a SOC analyst.

---

## 12. Evidence

### Splunk Detection Result

![Suspicious Network Detection](../screenshots/suspicious-network.png)

The screenshot should show the Splunk search result containing the PowerShell network connection.

---

## 13. Detection Workflow

```text id="fjis8u"
Sysmon Network Connection
          ↓
       EventCode 3
          ↓
    Splunk Index
      "windows"
          ↓
Search for PowerShell
          ↓
 Detection Triggered
          ↓
   SOC Investigation
          ↓
MITRE ATT&CK T1071.001
          ↓
 Correlation & Tuning
```

---

## 14. Detection Engineering Summary

This detection demonstrates:

* Sysmon Network Connection analysis
* PowerShell network monitoring
* SPL filtering
* Network investigation
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
