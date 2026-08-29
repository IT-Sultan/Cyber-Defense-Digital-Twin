# System Architecture

## Overview

The Cyber Defense Digital Twin processes security telemetry and converts raw events into meaningful SOC insights.

## Architecture Flow

Raw Security Events
→ Data Preprocessing
→ Feature Engineering
→ Detection Engine
→ Machine Learning
→ Event Correlation
→ MITRE ATT&CK Mapping
→ Attack Graph
→ SOC Dashboard

## Components

### Data Preprocessing
Cleans and standardizes raw security events.

### Detection Engine
Applies security rules and identifies suspicious activity.

### Machine Learning
Detects anomalous behavior and generates anomaly scores.

### Event Correlation
Links related events using time user host and process information.

### MITRE ATT&CK
Maps detected behavior to tactics and techniques.

### Attack Graph
Builds relationships between events hosts users and processes.

### SOC Dashboard
Displays alerts attack timelines MITRE mappings and attack paths.
