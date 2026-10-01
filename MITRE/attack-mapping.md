MITRE ATT&CK Mapping
1. Overview

This document maps the five Splunk detections in this project to relevant MITRE ATT&CK techniques.

MITRE ATT&CK provides a common framework for describing adversary behaviors and techniques used during cyber attacks.

The mappings in this project are based on the behavior represented by the synthetic Windows and Sysmon-style telemetry.

Note: The dataset used in this project is synthetic lab telemetry. MITRE mappings represent the behavior simulated by the test data and do not indicate that a real attack occurred.

2. Detection-to-MITRE Mapping
Detection	EventCode	MITRE Technique	Technique ID
Brute Force Authentication	4625	Brute Force	T1110
Suspicious PowerShell	4104	PowerShell	T1059.001
Suspicious Process Creation	1	Command and Scripting Interpreter	T1059
LSASS Access	10	OS Credential Dumping: LSASS Memory	T1003.001
Suspicious Network Connection	3	Application Layer Protocol: Web Protocols	T1071.001
