# Continuous Phishing Email Detector

A lightweight, round-the-clock Python script that connects to your IMAP email account and automatically detects and quarantines phishing emails. 

It features two modes of operation:
1. **Heuristics-Only Mode (Local):** Fast, rule-based detection that catches mismatched sender domains, suspicious keywords, and sketchy IP-based URLs.
2. **Gemini AI Mode (Advanced):** Uses Google's Gemini 2.5 Flash API to analyze the deep context of the email, drastically reducing false positives and catching complex social engineering attacks.

## Prerequisites

- Python 3.8+
- An email account with IMAP enabled (e.g., Gmail, Outlook). 
  *Note: For Gmail/Outlook, you will need to generate an **App Password**. Do not use your primary account password.*

## Installation

1. Clone or download this repository.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy the configuration template:
   ```bash
   cp .env.example .env
   ```

## Configuration

Open the `.env` file and fill in your credentials:

```env
IMAP_SERVER=imap.gmail.com
EMAIL_ACCOUNT=your_email@gmail.com
EMAIL_PASSWORD=your_app_password

# How often to check for new emails (in seconds)
CHECK_INTERVAL_SECONDS=300

# The folder to move phishing emails into
QUARANTINE_FOLDER=Quarantine

# [OPTIONAL] Gemini API Key for Advanced AI Detection
GEMINI_API_KEY=your_gemini_api_key_here
```

## Usage

Run the main script to start the background monitoring loop:

```bash
python main.py
```

The script will remain active, checking your inbox every 5 minutes (or whatever interval you configured). If it detects a phishing attempt, it will automatically move the email to your designated `Quarantine` folder.
