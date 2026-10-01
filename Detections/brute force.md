# Brute Force Authentication Detection

## 1. Objective

Detect multiple failed authentication attempts that may indicate
a brute-force attack against a user account.

---

## 2. Data Source

- SIEM: Splunk Enterprise
- Log Source: Windows Security Events
- Index: `windows`
- Event ID: `4625`
- Event Description: Failed logon

---

## 3. Detection Logic

The detection identifies 3 or more failed authentication attempts
from the same source IP against the same user within a 5-minute
time window.

---

## 4. SPL Detection Query

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time,src_ip,user
| where failed_attempts >= 3
