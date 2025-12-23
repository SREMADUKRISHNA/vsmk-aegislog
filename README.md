# VSMK-AegisLog

**VSMK-AegisLog** is an advanced command-line tool designed for automated log analysis and threat detection. It utilizes a hybrid rule-based machine learning model to score potential security threats and generates human-readable, AI-style summaries of system activity.

## Features

- **Multi-Format Support**: Parses standard SSH logs and Apache Access logs.
- **Intrusion Detection**: Identifies failed login bursts, brute-force attempts, and suspicious IP addresses.
- **Threat Scoring**: Assigns a deterministic threat score (0-100) using a logistic regression-based heuristic model.
- **AI-Style Summaries**: Generates actionable security insights and mitigation advice without external APIs.
- **Production Ready**: Modular architecture, robust error handling, and professional CLI output.

## Installation

1.  **Prerequisites**: Python 3.10 or higher.
2.  **Clone/Setup**: Ensure you are in the project directory.
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: The tool works with degraded output if dependencies are missing)*

## Usage

### Quick Start (Default Demo)
Run the tool without arguments to analyze the included sample SSH log:
```bash
python3 main.py
```

### Analyze Custom Logs
Specify a log file and its type:
```bash
# Analyze an SSH log
python3 main.py --log /var/log/auth.log --type ssh

# Analyze an Apache log
python3 main.py --log /var/log/apache2/access.log --type apache
```

## Project Structure

- `main.py`: CLI entry point.
- `parser.py`: Log parsing logic (Regex-based).
- `analyzer.py`: Feature extraction and statistics aggregation.
- `threat_model.py`: Mathematical model for threat scoring.
- `ai_summary.py`: Natural language generation for reports.
- `data/sample_logs/`: Contains realistic sample data for testing.

## License

MIT License. See `LICENSE` file for details.

---
*Built by VSMK.*
