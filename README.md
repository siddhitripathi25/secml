# SecML

> **AI/ML-Powered Behavioral Security Analyzer for the Terminal**

SecML is a terminal-based, read-only security tool that analyzes system behavior to identify potentially suspicious or anomalous activity using **rule-based detection and machine learning**.

**Disclaimer**: SecML is an educational security project. Behavioral anomalies detected by SecML represent potentially suspicious activity and a recommendation for further investigation. They **do not** automatically indicate a confirmed system compromise or the presence of malware.

## Architecture

SecML operates a sequential pipeline:
1. **Collectors**: Gathers read-only telemetry (Processes, Network Connections, System Info).
2. **Feature Extraction**: Converts raw telemetry into numerical behavioral features.
3. **Rule Detection**: Compares features against predefined heuristics.
4. **ML Anomaly Detection**: Uses Isolation Forest to compare current behavior against a learned baseline.
5. **Risk Scoring**: Combines results into a 0–100 risk score.
6. **CLI Display**: Presents clear, professional terminal reports.

## Installation

Ensure you have Python 3.11+ installed.

```bash
# Clone the repository
git clone https://github.com/siddhitripathi25/secml.git
cd secml

# Install dependencies and the package in editable mode
pip install -e .
```

## Available CLI Commands

SecML provides two primary orchestration commands:

* `secml scan`: Runs a one-time behavioral security scan of the local machine.
* `secml monitor`: Runs a continuous behavioral security scan in the terminal (stops on `Ctrl+C`).
* `secml --help`: Displays the help menu.
* `secml --version`: Displays the current version.

*(Note: Telemetry collection and baseline training are available via the Python API, but orchestrated for the user through the `scan` and `monitor` commands.)*

## Example Usage

Run a single scan:
```bash
secml scan
```

Run continuous monitoring (every 5 seconds):
```bash
secml monitor --interval 5
```

## Risk Levels

The 0–100 risk score is categorized into the following levels:
* **SAFE** (0–20): Normal system behavior.
* **LOW** (21–40): Minor deviations; typically safe.
* **MEDIUM** (41–60): Noticeable anomalies or rule triggers. Warrants a quick look.
* **HIGH** (61–80): Highly suspicious behavior. Investigation strongly recommended.
* **CRITICAL** (81–100): Severe behavioral anomalies indicating potential threat activity.

## Limitations

* SecML does not perform packet capture (PCAP) or deep packet inspection.
* SecML is completely read-only; it will not terminate processes, modify firewall rules, or automatically remediate threats.
* ML anomaly detection requires a valid baseline to function. If no baseline is present, the ML phase is safely skipped.
* Designed for educational and local analysis purposes rather than enterprise deployment.

## License

MIT
