#!/usr/bin/env python3
"""
Insider Threat Detection - Pipeline Runner

This script runs the complete detection pipeline:
1. Collects logs from various sources
2. Applies rule-based detection across all log sources
3. Outputs alerts to data/alerts.csv
"""

import os
import pandas as pd
from datetime import datetime, timedelta
import detector

def run_pipeline():
    """
    Run the complete insider threat detection pipeline
    """
    print(f"[{datetime.now()}] Running insider threat detection pipeline...")
    
    # 1. Load all log files
    logs = load_logs()
    
    # 2. Apply detection algorithms
    alerts = detect_threats(logs)
    
    # 3. Save the new alerts
    save_alerts(alerts)
    
    print(f"[{datetime.now()}] Pipeline execution complete.")

def load_logs():
    """
    Load all log files from the data directory
    
    Returns:
        dict: Dictionary containing DataFrames for each log type
    """
    print(f"[{datetime.now()}] Loading log files...")
    
    logs = {
        'kubernetes': None,
        'container': None,
        'network': None,
        'auth': None,
        'cicd': None,
        'system': None
    }
    
    # Path to data directory
    data_dir = "data"
    
    # Check if the data directory exists
    if not os.path.exists(data_dir):
        print(f"Data directory {data_dir} not found")
        return logs
    
    try:
        # Load kubernetes logs
        k8s_path = os.path.join(data_dir, "kubernetes_logs.csv")
        if os.path.exists(k8s_path):
            logs['kubernetes'] = pd.read_csv(k8s_path)
            if 'timestamp' in logs['kubernetes'].columns:
                logs['kubernetes']['timestamp'] = pd.to_datetime(logs['kubernetes']['timestamp'])
        
        # Load container logs
        container_path = os.path.join(data_dir, "container_logs.csv")
        if os.path.exists(container_path):
            logs['container'] = pd.read_csv(container_path)
            if 'timestamp' in logs['container'].columns:
                logs['container']['timestamp'] = pd.to_datetime(logs['container']['timestamp'])
        
        # Load network logs
        network_path = os.path.join(data_dir, "network_logs.csv")
        if os.path.exists(network_path):
            logs['network'] = pd.read_csv(network_path)
            if 'timestamp' in logs['network'].columns:
                logs['network']['timestamp'] = pd.to_datetime(logs['network']['timestamp'])
        
        # Load auth logs
        auth_path = os.path.join(data_dir, "authentication_logs.csv")
        if os.path.exists(auth_path):
            logs['auth'] = pd.read_csv(auth_path)
            if 'timestamp' in logs['auth'].columns:
                logs['auth']['timestamp'] = pd.to_datetime(logs['auth']['timestamp'])
        
        # Load CICD logs
        cicd_path = os.path.join(data_dir, "cicd_logs.csv")
        if os.path.exists(cicd_path):
            logs['cicd'] = pd.read_csv(cicd_path)
            if 'timestamp' in logs['cicd'].columns:
                logs['cicd']['timestamp'] = pd.to_datetime(logs['cicd']['timestamp'])
        
        # Load system logs
        system_path = os.path.join(data_dir, "system_logs.csv")
        if os.path.exists(system_path):
            logs['system'] = pd.read_csv(system_path)
            if 'timestamp' in logs['system'].columns:
                logs['system']['timestamp'] = pd.to_datetime(logs['system']['timestamp'])
                
        # Log the number of records loaded for each log type
        for log_type, df in logs.items():
            count = 0 if df is None else len(df)
            print(f"Loaded {count} {log_type} logs")
            
        return logs
        
    except Exception as e:
        print(f"Error loading log data: {str(e)}")
        return logs

def detect_threats(logs):
    """
    Apply detection algorithms to the logs
    
    Args:
        logs (dict): Dictionary containing DataFrames for each log type
        
    Returns:
        DataFrame: Alerts generated from the detection
    """
    print(f"[{datetime.now()}] Applying threat detection rules...")
    
    # Apply detection rules from detector.py
    alerts = detector.detect_threats(logs)
    
    print(f"Generated {len(alerts)} alerts")
    
    return alerts

def save_alerts(new_alerts):
    """
    Save the generated alerts to data/alerts.csv
    
    Args:
        new_alerts (DataFrame): Alerts generated from the detection
    """
    alerts_path = "data/alerts.csv"
    
    # Create a default alerts file if it doesn't exist or if new_alerts is empty
    if not os.path.exists(alerts_path) or new_alerts.empty:
        ensure_alerts_file_exists()
        
        # If there are new alerts, append them to the default file
        if not new_alerts.empty:
            existing_alerts = pd.read_csv(alerts_path)
            if 'timestamp' in existing_alerts.columns:
                existing_alerts['timestamp'] = pd.to_datetime(existing_alerts['timestamp'], format='ISO8601')
            
            combined_alerts = pd.concat([existing_alerts, new_alerts], ignore_index=True)
            combined_alerts.to_csv(alerts_path, index=False)
            print(f"Added {len(new_alerts)} new alerts to the alerts file")
    else:
        # Append new alerts to existing alerts
        existing_alerts = pd.read_csv(alerts_path)
        if 'timestamp' in existing_alerts.columns:
            # Use format='ISO8601' to handle various ISO8601 formats including those with timezone
            existing_alerts['timestamp'] = pd.to_datetime(existing_alerts['timestamp'], format='ISO8601')
        
        combined_alerts = pd.concat([existing_alerts, new_alerts], ignore_index=True)
        
        # Sort by timestamp (newest first) and keep only the most recent 100 alerts
        combined_alerts = combined_alerts.sort_values(by='timestamp', ascending=False)
        if len(combined_alerts) > 100:
            combined_alerts = combined_alerts.head(100)
            
        combined_alerts.to_csv(alerts_path, index=False)
        print(f"Updated alerts file with {len(new_alerts)} new alerts (total: {len(combined_alerts)})")

def ensure_alerts_file_exists():
    """Ensure that an alerts.csv file exists for the dashboard to read"""
    alerts_path = "data/alerts.csv"
    
    # Create a default alerts file if it doesn't exist
    if not os.path.exists(alerts_path):
        print(f"[{datetime.now()}] Creating default alerts file at {alerts_path}")
        
        # Create a simple DataFrame for demo purposes
        now = datetime.now()
        
        alerts = [
            {
                'timestamp': now - timedelta(minutes=15),
                'username': 'system_admin',
                'alert_type': 'Authentication',
                'severity': 'Medium',
                'resource': 'Login System',
                'description': 'Multiple failed login attempts',
                'source_ip': '192.168.1.100',
                'event_details': 'Failed password authentication'
            },
            {
                'timestamp': now - timedelta(minutes=10),
                'username': 'app_service',
                'alert_type': 'System',
                'severity': 'High',
                'resource': 'Operating System',
                'description': 'Suspicious privilege elevation detected',
                'source_ip': '10.0.0.5',
                'event_details': 'sudo to root from user account'
            },
            {
                'timestamp': now - timedelta(minutes=5),
                'username': 'container_user',
                'alert_type': 'Container',
                'severity': 'Low',
                'resource': 'Container Runtime',
                'description': 'Unusual container activity detected',
                'source_ip': 'N/A',
                'event_details': 'Exec into container: alpine_debug'
            }
        ]
        
        # Create the DataFrame
        df = pd.DataFrame(alerts)
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(alerts_path), exist_ok=True)
        
        # Save to CSV
        df.to_csv(alerts_path, index=False)
        print(f"Created default alerts file with {len(alerts)} sample alerts")
    else:
        print(f"[{datetime.now()}] Alerts file already exists")

if __name__ == "__main__":
    run_pipeline()