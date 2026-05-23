# 🚨 Hospital Brute Force Detector

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Healthcare Security](https://img.shields.io/badge/Healthcare-Security%20Tool-red.svg)](https://github.com/anurzaddd)

> **Real-time brute force attack detection for hospital servers (Windows RDP / Linux SSH)** – sends Telegram alerts when suspicious activity is detected.

## 🔥 Why this is a bomb
- Hospitals are prime targets for **brute force attacks** on PACS, EHR, and domain controllers.
- This tool monitors **failed login attempts** and alerts security team **within minutes**.
- Can be scheduled via **cron / Task Scheduler** for 24/7 monitoring.
- Lightweight, no database, just pure Python.

## 🚀 Quick Start (Linux)
```bash
git clone https://github.com/anurzaddd/hospital-brute-force-detector.git
cd hospital-brute-force-detector
pip install requests
python detect_bruteforce.py --os linux --minutes 5 --threshold 10
