# Detection Engineering Methodology

## 1. Overview

This document describes the detection engineering methodology used in the Splunk Detection Engineering Lab.

The goal is to transform security telemetry into useful detection rules that can support SOC investigation and threat detection.

---

## 2. Detection Engineering Lifecycle

The project follows this lifecycle:

```text
Understand Threat Behavior
          ↓
Identify Required Telemetry
          ↓
Develop Detection Logic
          ↓
Write SPL Query
          ↓
Test Detection
          ↓
Analyze Results
          ↓
Map to MITRE ATT&CK
          ↓
Identify False Positives
          ↓
Tune Detection
          ↓
Document Detection
```

---

## 3. Step 1 — Understand the Threat Behavior

Before creating a detection, the behavior being detected is identified.

Examples used in this project include:

* Repeated failed authentication
* Suspicious PowerShell activity
* Suspicious process relationships
* LSASS process access
* Suspicious PowerShell network connections

Understanding the behavior helps determine which telemetry and detection logic are required.

---

## 4. Step 2 — Identify Required Telemetry

The appropriate event source is selected based on the behavior.

| Behavior              | Event | Telemetry        |
| --------------------- | ----: | ---------------- |
| Failed authentication |  4625 | Windows Security |
| PowerShell activity   |  4104 | PowerShell       |
| Process creation      |     1 | Sysmon           |
| LSASS access          |    10 | Sysmon           |
| Network connection    |     3 | Sysmon           |

---

## 5. Step 3 — Develop Detection Logic

Detection logic is developed using relevant fields and conditions.

Examples include:

* Event ID
* Source IP
* Username
* Process name
* Parent process
* Destination IP
* Destination port
* Suspicious command indicators
* Event frequency

The goal is to identify meaningful security behavior while avoiding unnecessary alerts.

---

## 6. Step 4 — Write SPL

Splunk Processing Language (SPL) is used to search and analyze the telemetry.

Example:

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time,src_ip,user
| where failed_attempts >= 3
```

This detection identifies repeated failed authentication attempts.

---

## 7. Step 5 — Test the Detection

Each detection is tested against the synthetic telemetry.

Testing verifies that:

* The query returns the expected events.
* The detection conditions work correctly.
* The expected behavior is identified.
* The detection does not fail because of incorrect field names or logic.

Testing results are documented in each detection file.

---

## 8. Step 6 — Analyze Detection Results

After execution, the returned events are reviewed.

Important fields may include:

* Timestamp
* Username
* Source IP
* Host
* Process
* Destination
* Event description

The analyst reviews the surrounding context instead of relying only on a single event.

---

## 9. Step 7 — MITRE ATT&CK Mapping

Relevant detections are mapped to MITRE ATT&CK techniques.

| Detection             | Technique |
| --------------------- | --------- |
| Brute Force           | T1110     |
| Suspicious PowerShell | T1059.001 |
| Suspicious Process    | T1059     |
| LSASS Access          | T1003.001 |
| Suspicious Network    | T1071.001 |

MITRE ATT&CK mapping provides a common framework for describing adversary behaviors.

---

## 10. Step 8 — False Positive Analysis

A detection can identify legitimate activity as well as suspicious activity.

Potential causes of false positives include:

* Normal administrative activity
* Security tools
* Automated scripts
* User mistakes
* Software deployment
* System processes
* Legitimate network connections

Each detection therefore includes false-positive considerations.

---

## 11. Step 9 — Detection Tuning

Detection rules can be improved by adjusting their conditions.

Possible tuning methods include:

* Adjusting thresholds
* Adjusting time windows
* Adding additional event fields
* Adding process context
* Adding user context
* Adding network context
* Excluding known legitimate activity
* Correlating multiple events

The goal is to improve detection quality while reducing unnecessary alerts.

---

## 12. Step 10 — Documentation

Each detection is documented with:

* Objective
* Data source
* Detection logic
* SPL query
* Query explanation
* MITRE ATT&CK mapping
* Test scenario
* Detection result
* Investigation steps
* False-positive considerations
* Tuning recommendations
* Evidence
* Detection status

This makes the detection reproducible and easier for another analyst to understand.

---

## 13. Detection Quality Considerations

A useful detection should ideally be:

### Relevant

It should identify behavior that is meaningful to the security team.

### Testable

The detection should be validated using known test data.

### Explainable

An analyst should understand why the event triggered.

### Investigable

The alert should provide enough context to begin an investigation.

### Tunable

The detection should allow improvements based on observed false positives.

### Documented

The detection logic and investigation process should be clearly recorded.

---

## 14. Project Detection Set

The project currently contains five detection rules:

```text
1. Brute Force Authentication
2. Suspicious PowerShell
3. Suspicious Process Creation
4. LSASS Access
5. Suspicious Network Connection
```

Together, these detections demonstrate multiple areas of SOC monitoring:

* Authentication monitoring
* Endpoint monitoring
* PowerShell monitoring
* Process monitoring
* Credential-access monitoring
* Network monitoring

---

## 15. Summary

The project demonstrates a practical detection engineering workflow using Splunk.

The workflow starts with security telemetry and ends with a tested, documented, and tunable detection rule.

```text
Telemetry
   ↓
Detection Logic
   ↓
SPL
   ↓
Testing
   ↓
Investigation
   ↓
MITRE Mapping
   ↓
Tuning
   ↓
Documentation
```

This methodology can be extended with additional telemetry sources, correlation rules, automated alerting, dashboards, and SOAR workflows.
