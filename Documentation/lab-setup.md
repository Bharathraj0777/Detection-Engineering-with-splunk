# Lab Setup

## Objective

Build a Splunk-based detection engineering environment for
developing and testing security detections.

## Environment

The project uses Splunk Enterprise as the SIEM platform.

Initially, Windows 10 VM telemetry was planned to be collected
using Splunk Universal Forwarder.

Due to VM resource limitations, synthetic security telemetry
was used for the initial detection engineering and testing phase.

## Architecture

Synthetic Security Telemetry
          ↓
       Splunk
          ↓
      SPL Queries
          ↓
     Detection Rules
          ↓
 Alerts / Investigation
          ↓
 MITRE ATT&CK Mapping

## Splunk Configuration

### Index

```text
windows
