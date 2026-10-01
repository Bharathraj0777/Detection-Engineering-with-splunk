# Brute Force Authentication Detection

## 1. Objective

Detect repeated failed authentication attempts that may indicate a brute-force attack against a user account.

The detection identifies multiple failed Windows authentication attempts from the same source IP against the same user within a defined time window.

---

## 2. Data Source

* **SIEM:** Splunk Enterprise
* **Log Source:** Windows Security Events
* **Index:** `windows`
* **Event ID:** `4625`
* **Event Description:** Failed logon
* **Telemetry Type:** Synthetic Windows security telemetry created for this lab

> **Note:** The dataset used in this project is synthetic lab telemetry created for detection-engineering testing. It does not represent a real-world incident.

---

## 3. Detection Logic

The detection looks for:

* Windows failed logon events (`EventCode=4625`)
* From the same source IP
* Against the same username
* Within a 5-minute time window
* With 3 or more failed attempts

### Detection Threshold

| Parameter         | Value                |
| ----------------- | -------------------- |
| Event             | 4625                 |
| Failure threshold | 3 attempts           |
| Time window       | 5 minutes            |
| Grouping          | Source IP + Username |

---

## 4. SPL Detection Query

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time,src_ip,user
| where failed_attempts >= 3
```

### Query Explanation

**`index=windows`**

Searches the Windows index containing the imported security telemetry.

**`EventCode=4625`**

Filters for failed Windows authentication attempts.

**`bin _time span=5m`**

Groups events into 5-minute time windows.

**`stats count as failed_attempts by _time,src_ip,user`**

Counts failed authentication attempts for each source IP and username combination.

**`where failed_attempts >= 3`**

Returns only activity where at least 3 failed attempts occurred.

---

## 5. MITRE ATT&CK Mapping

### T1110 — Brute Force

The detection maps to **MITRE ATT&CK T1110 (Brute Force)** because repeated authentication failures can be associated with attempts to guess or obtain valid credentials.

**Technique:** T1110
**Tactic:** Credential Access

---

## 6. Test Scenario

### Scenario

A source generates multiple failed authentication attempts against the same user account within a short period.

### Test Data

* **Source IP:** `10.0.2.50`
* **Username:** `alice`
* **Failed attempts:** `4`
* **Detection threshold:** `3`
* **Time window:** `5 minutes`

The test data was intentionally created to exceed the detection threshold.

---

## 7. Detection Result

**Status: Tested Successfully**

The detection successfully identified repeated failed authentication attempts from the same source IP against the same user.

### Observed Result

| Field           | Result      |
| --------------- | ----------- |
| Source IP       | `10.0.2.50` |
| Username        | `alice`     |
| Failed attempts | `4`         |
| Threshold       | `3`         |
| Time window     | `5 minutes` |
| Detection       | Triggered   |

The detection triggered because the observed number of failed attempts (`4`) exceeded the configured threshold (`3`).

---

## 8. Investigation

When this detection generates an alert, a SOC analyst should investigate the following:

### Source Investigation

* Identify the source IP address.
* Determine whether the source is an expected workstation, server, or administrator system.
* Check whether the source generated other suspicious activity.

### Account Investigation

* Identify the targeted username.
* Determine whether the account is a normal user, administrator, or service account.
* Check whether the account experienced successful authentication after the failures.

### Timeline Investigation

Review the authentication activity around the detection time.

Important questions include:

1. How many failed attempts occurred?
2. Were the attempts concentrated within a short period?
3. Was there a successful login after the failures?
4. Did the same source IP perform other suspicious activity?
5. Is the source IP expected in the environment?

---

## 9. False Positive Considerations

Repeated failed authentication does not automatically mean a brute-force attack.

Possible legitimate causes include:

* User entering an incorrect password multiple times.
* Expired credentials.
* Password changed but an old password is still being used.
* Saved credentials containing an outdated password.
* Automated services using outdated credentials.
* Administrative or troubleshooting activity.

Therefore, the detection should be investigated and correlated with other telemetry before treating the activity as malicious.

---

## 10. Detection Tuning

The detection can be tuned to reduce false positives and improve detection quality.

Possible tuning approaches:

* Increase or decrease the failed-attempt threshold.
* Adjust the time window.
* Exclude known legitimate service accounts when appropriate.
* Exclude known systems that generate expected authentication failures.
* Correlate failed logons with successful logons.
* Add additional conditions such as unusual source IPs or unusual login times.

### Example

A production environment may require a higher threshold than this lab depending on normal authentication behavior.

The threshold should be validated against the organization's baseline rather than blindly using a fixed value.

---

## 11. Evidence

### Splunk Detection Result

Add the screenshot of the successful detection test below.

```markdown
![Brute Force Detection Result](../screenshots/brute-force-detection.png)
```

The screenshot should show the Splunk search result containing the detected source IP, username, and failed-attempt count.

---

## 12. Detection Workflow

```text
Windows Authentication Events
            ↓
       EventCode 4625
            ↓
      Splunk Index
        "windows"
            ↓
       SPL Detection
            ↓
   3+ failures / 5 min
            ↓
    Detection Triggered
            ↓
       Investigation
            ↓
     MITRE ATT&CK T1110
            ↓
    Tuning / Validation
```

---

## 13. Detection Engineering Summary

This detection demonstrates a basic SIEM detection-engineering workflow:

* Log ingestion
* Event filtering
* Time-based aggregation
* Threshold-based detection
* MITRE ATT&CK mapping
* Detection testing
* Investigation workflow
* False-positive analysis
* Detection tuning

---

## 14. Status

**Detection:** Completed
**Testing:** Successful
**MITRE Mapping:** Completed
**Documentation:** Completed


