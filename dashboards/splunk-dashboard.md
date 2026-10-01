# Splunk Detection Dashboard

## 1. Overview

This document describes the Splunk dashboard designed for monitoring the five detections developed in this project.

The dashboard provides a centralized view of suspicious authentication activity, PowerShell activity, process creation, LSASS access, and network connections.

The project uses synthetic Windows and Sysmon-style telemetry imported into Splunk.

---

# 2. Dashboard Purpose

The dashboard is designed to help a SOC analyst quickly identify:

* Authentication attacks
* Suspicious PowerShell activity
* Suspicious process execution
* Potential LSASS access
* Suspicious network connections

The dashboard can be used as an initial investigation interface before examining individual events.

---

# 3. Data Source

### Splunk Index

```text
windows
```

### Main Telemetry

| EventCode | Telemetry               | Detection             |
| --------: | ----------------------- | --------------------- |
|      4625 | Failed Windows Logon    | Brute Force           |
|      4104 | PowerShell Script Block | Suspicious PowerShell |
|         1 | Process Creation        | Suspicious Process    |
|        10 | Process Access          | LSASS Access          |
|         3 | Network Connection      | Suspicious Network    |

---

# 4. Dashboard Panels

The dashboard contains the following recommended panels.

## Panel 1 — Failed Authentication Attempts

### Purpose

Shows failed authentication activity that may indicate brute-force behavior.

### SPL

```spl
index=windows EventCode=4625
| timechart count by src_ip
```

### Recommended Visualization

**Line Chart**

### Useful Fields

* `_time`
* `src_ip`
* `user`
* EventCode

---

# 5. Panel 2 — Suspicious PowerShell Activity

### Purpose

Displays PowerShell activity containing suspicious indicators.

### SPL

```spl
index=windows EventCode=4104
| search description="*EncodedCommand*" OR description="*Invoke-WebRequest*"
| timechart count by user
```

### Recommended Visualization

**Column Chart**

### Useful Fields

* `_time`
* `user`
* `host`
* `description`

---

# 6. Panel 3 — Suspicious Process Creation

### Purpose

Displays suspicious process creation involving Microsoft Word and

