# Splunk Detection Engineering Lab Setup

## 1. Project Overview

This project demonstrates the design, testing, and documentation of SIEM detection rules using Splunk Enterprise.

The lab focuses on detecting common security behaviors using Windows Security Events and Sysmon-style telemetry.

The project includes:

* Splunk Enterprise
* Windows security telemetry
* Sysmon-style events
* SPL detection rules
* MITRE ATT&CK mapping
* Detection testing
* False-positive analysis
* Detection tuning
* SOC investigation workflows

---

## 2. Lab Architecture

```text
Synthetic Windows / Sysmon Telemetry
                |
                v
        Splunk Enterprise
                |
                v
        Windows Index
          "windows"
                |
                v
        SPL Detection Rules
                |
                v
        Detection Results
                |
        +-------+-------+
        |       |       |
        v       v       v
     Alert  Investigation  Tuning
                |
                v
       MITRE ATT&CK Mapping
```

---

## 3. SIEM Platform

### Splunk Enterprise

Splunk Enterprise is used as the central SIEM platform for:

* Log ingestion
* Searching
* Detection development
* Event analysis
* Alerting
* Investigation
* Dashboard creation

---

## 4. Data Source

The project uses synthetic Windows and Sysmon-style security telemetry.

The dataset contains events representing:

* Failed authentication
* Successful authentication
* PowerShell activity
* Process creation
* LSASS process access
* Network connections

The data was created specifically for this lab to test detection logic.

> **Important:** The telemetry used in this project is synthetic and should not be interpreted as evidence from a real-world security incident.

---

## 5. Splunk Index

The imported telemetry is stored in the following Splunk index:

```text
windows
```

The index is used by the detection queries throughout this project.

Example:

```spl
index=windows
```

---

## 6. Telemetry Types

The project uses several Windows/Sysmon event types.

| Event Code | Event Type              | Purpose                      |
| ---------- | ----------------------- | ---------------------------- |
| 4625       | Failed Logon            | Brute-force detection        |
| 4624       | Successful Logon        | Authentication investigation |
| 4104       | PowerShell Script Block | PowerShell detection         |
| 1          | Process Creation        | Process detection            |
| 10         | Process Access          | LSASS access detection       |
| 3          | Network Connection      | Network detection            |

---

## 7. Detection Pipeline

The detection pipeline used in this project is:

```text
Telemetry
    ↓
Splunk Index
    ↓
SPL Query
    ↓
Detection Logic
    ↓
Test Scenario
    ↓
Detection Result
    ↓
Investigation
    ↓
MITRE ATT&CK Mapping
    ↓
Tuning
```

---

## 8. Detection Rules

The project currently contains five detection rules:

### 1. Brute Force Authentication

**Event:** 4625

**MITRE ATT&CK:** T1110

Detects multiple failed authentication attempts within a defined time window.

### 2. Suspicious PowerShell

**Event:** 4104

**MITRE ATT&CK:** T1059.001

Detects PowerShell activity containing configured suspicious indicators.

### 3. Suspicious Process Creation

**Event:** 1

**MITRE ATT&CK:** T1059

Detects potentially suspicious Office-to-command-interpreter process relationships.

### 4. LSASS Access

**Event:** 10

**MITRE ATT&CK:** T1003.001

Detects process-access activity involving LSASS.

### 5. Suspicious Network Connection

**Event:** 3

**MITRE ATT&CK:** T1071.001

Detects PowerShell-related network connection activity for investigation.

---

## 9. Project Limitations

This lab is designed for learning and portfolio demonstration.

Limitations include:

* Synthetic telemetry is used.
* The environment does not represent a production SOC.
* Detection thresholds are demonstration values.
* Network and endpoint context is limited.
* Detection results require analyst investigation.
* A detection alert does not automatically prove malicious activity.

---

## 10. Security Analysis Approach

The project follows a SOC-oriented investigation approach:

1. Identify suspicious telemetry.
2. Develop detection logic.
3. Test the detection.
4. Review detection results.
5. Investigate surrounding activity.
6. Map relevant behavior to MITRE ATT&CK.
7. Identify possible false positives.
8. Tune the detection.
9. Document the final rule.

---

## 11. Project Status

**Lab Setup:** Completed
**Telemetry:** Imported
**Detections:** Completed
**Detection Testing:** Completed
**Screenshots:** Completed
**SPL Rules:** Completed

