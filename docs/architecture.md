# SecML Architecture

## 1. Overview

SecML follows a modular architecture where system telemetry is collected, transformed into behavioral features, analyzed using rules and ML, and finally converted into a risk assessment.

```text
                    ┌──────────────┐
                    │   SecML CLI  │
                    └──────┬───────┘
                           │
                           ▼
                 ┌──────────────────┐
                 │ Data Collection  │
                 └────────┬─────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
         Processes      Network      System
             │            │            │
             └────────────┼────────────┘
                          ▼
                 ┌──────────────────┐
                 │ Feature Engine   │
                 └────────┬─────────┘
                          │
                 ┌────────┴─────────┐
                 ▼                  ▼
          ┌─────────────┐    ┌─────────────┐
          │ Rule Engine │    │  ML Engine  │
          └──────┬──────┘    └──────┬──────┘
                 │                  │
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │  Risk Scoring    │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   CLI Report     │
                 └──────────────────┘
```

## 2. Components

### CLI

Handles user commands such as:

```bash
secml scan
secml processes
secml network
secml baseline
secml monitor
```

The CLI is responsible for interaction and presentation, not detection logic.

### Data Collectors

Collect raw system telemetry.

```text
collectors/
├── process.py
├── network.py
└── system.py
```

### Feature Engine

Transforms raw telemetry into features suitable for behavioral analysis and ML.

```text
Raw Telemetry
      ↓
Feature Extraction
      ↓
Feature Vectors
```

### Rule Engine

Detects predefined suspicious patterns and produces security findings.

### ML Engine

Uses anomaly detection to identify behavior that differs from the expected baseline.

The initial ML approach will use **Isolation Forest**.

### Risk Engine

Combines rule-based findings, ML anomaly scores, and behavioral signals into a final risk score.

```text
Rule Score
    +
ML Score
    +
Behavior Score
    ↓
Risk Score: 0–100
```

## 3. Data Flow

```text
User
 ↓
CLI
 ↓
Collectors
 ↓
Raw Telemetry
 ↓
Feature Extraction
 ↓
Rule Detection + ML Detection
 ↓
Behavior Analysis
 ↓
Risk Scoring
 ↓
Terminal Report
```

## 4. Initial Scope

The 4-day MVP focuses on:

* Process monitoring
* Network monitoring
* System information
* Behavioral features
* Rule-based detection
* ML anomaly detection
* Baseline creation
* Risk scoring
* Terminal reporting

## 5. Future Scalability

The architecture is designed to later evolve into a centralized security platform.

```text
                 SecML Platform
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
           CLI              Web Dashboard
             │                   │
             └─────────┬─────────┘
                       ▼
                      API
                       │
               Detection Engine
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
         Agent 1    Agent 2    Agent N
            │          │          │
            └──────────┼──────────┘
                       ▼
               Centralized Storage
```

Future components may include:

* FastAPI
* PostgreSQL
* Redis
* Endpoint agents
* MITRE ATT&CK mapping
* Incident management
* Alerting
* Security dashboard
* SIEM integration
* Advanced ML models
