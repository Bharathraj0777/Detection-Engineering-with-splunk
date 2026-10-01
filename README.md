
# Splunk Detection Engineering Lab

## Overview

This project demonstrates a hands-on detection engineering workflow
using Splunk and synthetic Windows security telemetry.

The project focuses on developing, testing, investigating, and tuning
SIEM detection rules using SPL and mapping detections to MITRE ATT&CK.

## Objectives

- Understand SIEM-based detection engineering
- Develop SPL detection rules
- Analyze Windows security telemetry
- Detect suspicious authentication and endpoint activity
- Map detections to MITRE ATT&CK
- Investigate alerts
- Identify and reduce false positives

## Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- SPL
- Windows Event Logs
- Sysmon
- MITRE ATT&CK
- Kali Linux

## Project Architecture

Synthetic Security Logs
        ↓
     Splunk
        ↓
    SPL Queries
        ↓
   Detection Rules
        ↓
 Alerts & Investigation
        ↓
 MITRE ATT&CK Mapping
        ↓
 Detection Tuning

## Detection Use Cases

1. Brute-force authentication
2. Suspicious PowerShell activity
3. Suspicious process execution
4. LSASS access
5. Suspicious network activity

## Detection Engineering Workflow

Telemetry
→ Detection
→ Alert
→ Investigation
→ Tuning
→ MITRE ATT&CK Mapping

## Project Status

- [x] Splunk Enterprise setup
- [x] Windows index created
- [x] Synthetic security telemetry imported
- [ ] Brute-force detection
- [ ] PowerShell detection
- [ ] Process execution detection
- [ ] LSASS access detection
- [ ] Network detection
- [ ] Alert configuration
- [ ] Detection tuning
- [ ] SOC dashboard
- [ ] Final documentation
