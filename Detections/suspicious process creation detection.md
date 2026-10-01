# Suspicious Process Creation Detection

## 1. Objective

Detect potentially suspicious process execution patterns that may indicate malicious activity.

The detection focuses on process creation events where Microsoft Word (`WINWORD.EXE`) launches command interpreters such as PowerShell or Command Prompt.

This type of parent-child process relationship can require investigation because Office applications normally should not need to launch command interpreters during ordinary document usage.

---

## 2. Data Source

* **SIEM:** Splunk Enterprise
* **Log Source:** Sysmon
* **Index:** `windows`
* **Event ID:** `1`
* **Event Description:** Process Creation
* **Telemetry Type:** Synthetic lab telemetry created for this project

> **Note:** The dataset used in this project is synthetic lab telemetry created for detection-engineering testing. It does not represent a real-world incident.

---

## 3. Detection Logic

The detection searches for Sysmon Process Creation events where:

* `WINWORD.EXE` appears in the process relationship.
* PowerShell or Command Prompt is also involved.
* The activity is identified for further investigation.

### Suspicious Process Relationships

```text
WINWORD.EXE → powershell.exe
```

or

```text
WINWORD.EXE → cmd.exe
```

These relationships can be suspicious because malicious documents can sometimes be used to initiate command execution.

---

## 4. SPL Detection Query

```spl
index=windows EventCode=1
| search description="*WINWORD.EXE*"
| search description="*powershell.exe*" OR description="*cmd.exe*"
| stats count by _time,host,user,description
| sort - _time
```

---

## 5. Query Explanation

### `index=windows`

Searches the Windows telemetry stored in the Splunk `windows` index.

### `EventCode=1`

Filters for Sysmon Process Creation events.

### `description="*WINWORD.EXE*"`

Searches for Microsoft Word being involved in the process relationship.

### `description="*powershell.exe*" OR description="*cmd.exe*"`

Searches for PowerShell or Command Prompt being involved in the process relationship.

### `stats count`

Counts the matching events and groups them by:

* Time
* Host
* User
* Description

### `sort - _time`

Displays the newest events first.

---

## 6. MITRE ATT&CK Mapping

### T1059 — Command and Scripting Interpreter

**Tactic:** Execution

The detection focuses on suspicious use of command interpreters such as PowerShell and Command Prompt.

Depending on the exact command execution observed, the activity may also be mapped to a more specific sub-technique such as:

* **T1059.001 — PowerShell**
* **T1059.003 — Windows Command Shell**

The exact mapping should depend on the process and command-line activity observed during investigation.

---

## 7. Test Scenario

### Scenario

A Microsoft Word process launches a command interpreter.

The synthetic telemetry contains process relationships designed to test this detection.

### Test Data

Example process chain:

```text
WINWORD.EXE → powershell.exe
```

Another process relationship in the dataset is:

```text
powershell.exe → cmd.exe
```

The detection searches for the Word-to-command-interpreter relationship.

---

## 8. Detection Result

**Status: Tested Successfully**

The detection successfully identified a process creation event involving Microsoft Word and a command interpreter.

### Observed Activity

| Field         | Result           |
| ------------- | ---------------- |
| Event ID      | `1`              |
| Process       | `WINWORD.EXE`    |
| Child Process | `powershell.exe` |
| Event Type    | Process Creation |
| Detection     | Triggered        |

The process relationship was identified by the SPL detection query and requires investigation to determine whether the activity is legitimate or suspicious.

---

## 9. Investigation

When this detection generates an alert, a SOC analyst should investigate:

### Process Investigation

* Parent process
* Child process
* Process executable
* Process ID
* Parent process ID
* Command-line arguments
* Process execution time

### User Investigation

* Username associated with the process
* Whether the user normally uses Microsoft Word
* Whether the user initiated the activity

### Additional Investigation

Check for:

* PowerShell Script Block Logging events
* Network connections
* File creation
* Downloaded files
* Other process creation events
* Suspicious document activity
* Authentication events around the same time

Correlation with other telemetry can help determine whether the process relationship is legitimate or suspicious.

---

## 10. False Positive Considerations

Microsoft Word launching PowerShell or Command Prompt may occasionally occur during legitimate activity.

Possible causes include:

* Enterprise automation
* Administrative scripts
* Software deployment
* Office add-ins
* Security testing
* IT troubleshooting
* Legitimate document automation

Therefore, this detection should generate an investigation rather than automatically classify the activity as malicious.

---

## 11. Detection Tuning

Potential tuning approaches include:

* Identify known legitimate Office automation.
* Allowlist approved administrative scripts where appropriate.
* Exclude known enterprise management tools when justified.
* Add command-line analysis.
* Correlate process creation with PowerShell Event ID 4104.
* Correlate with network connections.
* Add user and host context.
* Establish a baseline of normal Office process behavior.

### Example Correlation

A stronger detection could correlate:

```text
WINWORD.EXE
      ↓
powershell.exe
      ↓
Network Connection
```

This provides more context than detecting the process relationship alone.

---

## 12. Evidence

### Splunk Detection Result

![Suspicious Process Detection](../screenshots/suspicious-process-creation-detection.png)


---

## 13. Detection Workflow

```text
Sysmon Process Creation
          ↓
     EventCode 1
          ↓
    Splunk Index
      "windows"
          ↓
Identify Office → Command Interpreter
          ↓
 Detection Triggered
          ↓
   SOC Investigation
          ↓
MITRE ATT&CK T1059
          ↓
 Correlation & Tuning
```

---

## 14. Detection Engineering Summary

This detection demonstrates:

* Sysmon Process Creation analysis
* Parent-child process investigation
* SPL filtering
* Suspicious process detection
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
