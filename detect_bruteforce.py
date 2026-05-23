#!/usr/bin/env python3
"""
Hospital Brute Force Detector
Monitors failed login attempts (SSH for Linux, Security log for Windows)
Sends alert via Telegram if threshold exceeded.
"""

import os
import time
import re
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# ============================================================
# Telegram bot setup (optional)
# ============================================================
def send_telegram_alert(bot_token, chat_id, message):
    """Send alert via Telegram bot"""
    try:
        import requests
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        r = requests.post(url, json=payload, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"[!] Telegram alert failed: {e}")
        return False

# ============================================================
# Linux: parse SSH auth log
# ============================================================
def parse_ssh_log(log_path="/var/log/auth.log", minutes=5, threshold=10):
    """Return dict of IP -> count of failed SSH attempts in last 'minutes' minutes"""
    cutoff = datetime.now() - timedelta(minutes=minutes)
    failed_ips = defaultdict(int)
    
    # Failed SSH patterns
    patterns = [
        r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
        r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)"
    ]
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                # parse syslog timestamp (simple approach)
                try:
                    # Example: "May 23 10:15:22 ..."
                    log_time_str = ' '.join(line.split()[:3])
                    log_time = datetime.strptime(f"{datetime.now().year} {log_time_str}", "%Y %b %d %H:%M:%S")
                except:
                    continue
                if log_time < cutoff:
                    continue
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        ip = match.group(1)
                        failed_ips[ip] += 1
                        break
    except FileNotFoundError:
        pass
    return failed_ips

# ============================================================
# Windows: parse Security log via PowerShell (requires admin)
# ============================================================
def parse_windows_security_log(minutes=5, threshold=10):
    """Call PowerShell to get failed login events (4625)"""
    import subprocess
    cutoff = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    ps_script = f"""
    $events = Get-EventLog -LogName Security -InstanceId 4625 -After '{cutoff}' -ErrorAction SilentlyContinue
    $events | ForEach-Object {{
        $ip = $_.ReplacementStrings[18]
        if ($ip) {{ Write-Output $ip }}
    }}
    """
    try:
        result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True, timeout=30)
        ips = result.stdout.strip().splitlines()
        failed_ips = defaultdict(int)
        for ip in ips:
            if ip and ip != "":
                failed_ips[ip] += 1
        return failed_ips
    except Exception as e:
        print(f"[!] Windows log error: {e}")
        return {}

# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Hospital Brute Force Detector")
    parser.add_argument("--os", choices=["linux", "windows"], default="linux", help="Operating system")
    parser.add_argument("--minutes", type=int, default=5, help="Time window in minutes")
    parser.add_argument("--threshold", type=int, default=10, help="Max failed attempts before alert")
    parser.add_argument("--telegram-bot-token", help="Telegram bot token")
    parser.add_argument("--telegram-chat-id", help="Telegram chat ID")
    parser.add_argument("--log-file", default="/var/log/auth.log", help="SSH log path (Linux only)")
    args = parser.parse_args()
    
    if args.os == "linux":
        failed = parse_ssh_log(args.log_file, args.minutes, args.threshold)
    else:
        failed = parse_windows_security_log(args.minutes, args.threshold)
    
    alerts = []
    for ip, count in failed.items():
        if count >= args.threshold:
            msg = f"🚨 <b>Brute Force Alert</b> 🚨\nIP: {ip}\nFailed attempts: {count}\nTime window: {args.minutes} minutes"
            alerts.append(msg)
            print(f"[!] Alert: {msg}")
    
    # Send to Telegram if configured
    if alerts and args.telegram_bot_token and args.telegram_chat_id:
        for alert in alerts:
            send_telegram_alert(args.telegram_bot_token, args.telegram_chat_id, alert)
    elif alerts:
        print("[*] No Telegram credentials provided. Print only.")
    else:
        print(f"[+] No brute force detected in last {args.minutes} minutes.")

if __name__ == "__main__":
    main( )
