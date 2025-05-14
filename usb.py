import os
import sys
import wmi
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import time  # Added for delay
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.ensemble import IsolationForest
import win32file

# Email settings (replace with your actual credentials and SMTP server)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "golurawat151106@gmail.com"
EMAIL_PASS = "cogh desa cexu anlu"  # Use an App Password if using Gmail
ALERT_EMAIL = "golurawat151106@gmail.com"

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".js", ".msi", ".cmd", "autorun.inf"]

# USB usage log
usb_usage_data = []

# Anomaly detector
isolation_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)

def send_email_alert(device_id, alert_message):
    try:
        msg = MIMEText(f"Alert for USB Device ID: {device_id}\n\n{alert_message}")
        msg['Subject'] = 'USB Device Alert'
        msg['From'] = EMAIL_USER
        msg['To'] = ALERT_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, ALERT_EMAIL, msg.as_string())
        print(f"✅ Alert sent for device: {device_id}")
    except Exception as e:
        print(f"❌ Failed to send alert: {e}")

def log_usb_usage(device_id):
    usb_usage_data.append({
        "device_id": device_id,
        "timestamp": datetime.now(),
        "action": "Connected"
    })

def get_usb_drives():
    drives = []
    bitmask = win32file.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drive_letter = f"{chr(65 + i)}:\\"
            type_drive = win32file.GetDriveType(drive_letter)
            if type_drive == win32file.DRIVE_REMOVABLE:
                print(f"Detected drive: {drive_letter}")  # Debugging: log detected drives
                drives.append(drive_letter)
    return drives

def scan_for_suspicious_files(drive):
    suspicious_found = []
    print(f"🔎 Scanning {drive} for suspicious files...")
    for root, dirs, files in os.walk(drive):
        for file in files:
            print(f"Checking file: {file}")  # Debugging: log all files being checked
            lower = file.lower()
            if any(lower.endswith(ext) or ext in lower for ext in SUSPICIOUS_EXTENSIONS):
                full_path = os.path.join(root, file)
                suspicious_found.append(full_path)
                print(f"⚠️ Suspicious file: {full_path}")
    return suspicious_found

def monitor_usb_real_time():
    c = wmi.WMI()
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_USBHub")

    print("🔍 Monitoring real-time USB activity (Press Ctrl+C to stop)...")
    try:
        while True:
            usb_event = watcher()
            try:
                device_name = usb_event.Name
                device_id = usb_event.DeviceID
                pnp_id = usb_event.PNPDeviceID
                print(f"\n📦 [{datetime.now().strftime('%H:%M:%S')}] USB Device Connected!")
                print(f"  ➤ Name: {device_name}")
                print(f"  ➤ Device ID: {device_id}")
                print(f"  ➤ PNP ID: {pnp_id}")
                log_usb_usage(device_id)

                # Wait to ensure the drive is fully mounted
                time.sleep(5)  # Give system time to mount the USB drive

                # Scan drives
                drives = get_usb_drives()
                all_suspicious = []
                for drive in drives:
                    all_suspicious += scan_for_suspicious_files(drive)
                if all_suspicious:
                    alert_msg = "\n".join(all_suspicious)
                    send_email_alert(device_id, alert_msg)

            except AttributeError:
                print("⚠ USB event detected, but could not read device details.")
    except KeyboardInterrupt:
        print("🛑 Monitoring stopped by user.")

def visualize_usb_activity():
    if not usb_usage_data:
        print("ℹ No USB activity to visualize.")
        return

    timestamps = [entry["timestamp"] for entry in usb_usage_data]
    sns.histplot(timestamps, kde=True)
    plt.title("USB Device Connection Times")
    plt.xlabel("Timestamp")
    plt.ylabel("Frequency")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def detect_anomalies():
    if len(usb_usage_data) < 2:
        print("ℹ Not enough data for anomaly detection.")
        return

    X = np.random.rand(len(usb_usage_data), 2)  # Placeholder features
    isolation_forest.fit(X)
    predictions = isolation_forest.predict(X)

    anomalies = [usb_usage_data[i] for i, p in enumerate(predictions) if p == -1]
    if anomalies:
        print(f"⚠ {len(anomalies)} anomalous USB events detected!")
        for a in anomalies:
            print(f"  ➤ Device: {a['device_id']} at {a['timestamp']}")
    else:
        print("✅ No anomalies found in USB activity.")

if __name__ == "__main__":
    if os.name != "nt":
        print("❌ This script only runs on Windows.")
        sys.exit(1)

    print("🔒 Real-Time USB Monitoring with Suspicious File Detection\n")
    monitor_usb_real_time()
