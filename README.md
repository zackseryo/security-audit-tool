# 🔒 Network Security Audit Tool

An AI-powered CLI tool that performs comprehensive security audits on any domain and generates a professional PDF report.

## Features

- WHOIS information lookup
- DNS records analysis (A, MX, TXT, NS)
- Security headers check
- IP & hosting information
- AI-powered security analysis and recommendations
- Professional PDF report generation

## Requirements

- Python 3.x
- OpenRouter API key (free tier available)

## Installation

git clone https://github.com/YOUR_USERNAME/security-audit-tool.git
cd security-audit-tool
pip install requests python-whois dnspython reportlab

## Configuration

Open `security_audit.py` and replace:
OPENROUTER_API_KEY = "your-openrouter-api-key-here"

Get your free API key at: https://openrouter.ai

## Usage

python security_audit.py

Enter any domain when prompted. The tool will generate a PDF report on your Desktop.

## Sample Output

The tool generates a comprehensive PDF report including:
- Executive Summary
- Risk Level Assessment
- Security Headers Status
- Infrastructure Details
- Actionable Recommendations

## Tech Stack

- Python 3
- ReportLab (PDF generation)
- OpenRouter AI API
- python-whois
- dnspython

## License

MIT License
