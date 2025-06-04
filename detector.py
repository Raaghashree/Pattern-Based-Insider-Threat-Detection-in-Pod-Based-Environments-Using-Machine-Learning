#!/usr/bin/env python3
"""
Insider Threat Detection - Rule-Based Detector

This module contains rule-based detection logic for identifying potential
insider threats across various log sources.
"""

import pandas as pd
import numpy as np
from datetime import datetime, time

def detect_threats(logs):
    """
    Apply rule-based threat detection across multiple log sources
    
    Args:
        logs (dict): Dictionary containing DataFrames for each log type
        
    Returns:
        DataFrame: Alerts generated from the detection rules
    """
    alerts = []
    
    # Ensure we have logs to process
    if not logs or all(df is None or df.empty for df in logs.values()):
        return pd.DataFrame()
    
    # Convert all timestamps to datetime if they're not already
    for log_type, df in logs.items():
        if df is not None and not df.empty and 'timestamp' in df.columns:
            if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                logs[log_type]['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Apply detection rules to each log source
    alerts.extend(detect_authentication_threats(logs.get('auth')))
    alerts.extend(detect_kubernetes_threats(logs.get('kubernetes')))
    alerts.extend(detect_container_threats(logs.get('container')))
    alerts.extend(detect_network_threats(logs.get('network')))
    alerts.extend(detect_cicd_threats(logs.get('cicd')))
    alerts.extend(detect_system_threats(logs.get('system')))
    
    # Create a DataFrame from the alerts
    if alerts:
        return pd.DataFrame(alerts)
    
    return pd.DataFrame()

def is_after_hours(timestamp):
    """Check if the activity occurred during after-hours (8PM-6AM)"""
    if timestamp is None or pd.isna(timestamp):
        return False
        
    hour = timestamp.hour
    return hour >= 20 or hour < 6

def is_weekend(timestamp):
    """Check if the activity occurred during the weekend"""
    if timestamp is None or pd.isna(timestamp):
        return False
    
    return timestamp.weekday() >= 5  # 5 = Saturday, 6 = Sunday

def is_external_ip(ip):
    """Check if the IP is an external IP address"""
    if pd.isna(ip) or not ip:
        return False
    
    # Simple check: External IPs don't start with 10., 172.16-31., or 192.168.
    if ip.startswith(('10.', '192.168.')):
        return False
    if ip.startswith('172.'):
        second_octet = int(ip.split('.')[1])
        if 16 <= second_octet <= 31:
            return False
    
    return True

def detect_authentication_threats(auth_logs):
    """Detect threats in authentication logs"""
    alerts = []
    
    if auth_logs is None or auth_logs.empty:
        return alerts
    
    # Rule: Failed login attempts (3 or more)
    if 'user_id' in auth_logs.columns and 'status' in auth_logs.columns:
        # Group by user_id and count failed logins
        failed_logins = auth_logs[auth_logs['status'] == 'failure'].groupby('user_id').size()
        for user_id, count in failed_logins.items():
            if count >= 3:
                last_failure = auth_logs[(auth_logs['user_id'] == user_id) & 
                                         (auth_logs['status'] == 'failure')].iloc[-1]
                
                alerts.append({
                    'timestamp': last_failure['timestamp'],
                    'username': user_id,
                    'alert_type': 'Authentication',
                    'severity': 'High',
                    'resource': 'Login System',
                    'description': f'Multiple failed login attempts ({count}) for user {user_id}',
                    'source_ip': last_failure.get('source_ip', 'Unknown'),
                    'event_details': f"Last attempt at {last_failure['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                })
    
    # Rule: Successful login after hours
    for _, row in auth_logs.iterrows():
        if 'status' in row and row.get('status') == 'success' and 'timestamp' in row:
            if is_after_hours(row['timestamp']):
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user_id', 'unknown'),
                    'alert_type': 'Authentication',
                    'severity': 'Medium',
                    'resource': 'Login System',
                    'description': f'After-hours login for user {row.get("user_id", "unknown")}',
                    'source_ip': row.get('source_ip', 'Unknown'),
                    'event_details': f"Login at {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                })
    
    # Rule: Login from external IP
    for _, row in auth_logs.iterrows():
        if 'source_ip' in row and is_external_ip(row['source_ip']):
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user_id', 'unknown'),
                'alert_type': 'Authentication',
                'severity': 'Medium',
                'resource': 'Login System',
                'description': f'Login from external IP for user {row.get("user_id", "unknown")}',
                'source_ip': row['source_ip'],
                'event_details': f"External IP access from {row['source_ip']}"
            })
    
    return alerts

def detect_kubernetes_threats(k8s_logs):
    """Detect threats in Kubernetes logs"""
    alerts = []
    
    if k8s_logs is None or k8s_logs.empty:
        return alerts
    
    # Rule: Unauthorized resource access or deletion
    sensitive_resources = ['secret', 'role', 'rolebinding', 'clusterrole', 'clusterrolebinding']
    
    for _, row in k8s_logs.iterrows():
        # Check for sensitive resource operations
        if 'resource' in row and any(res in str(row['resource']).lower() for res in sensitive_resources):
            if 'action' in row and row['action'] in ['delete', 'update', 'create', 'patch']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user', 'unknown'),
                    'alert_type': 'Kubernetes',
                    'severity': 'High',
                    'resource': f"K8s {row.get('resource', 'resource')}",
                    'description': f"Sensitive K8s {row.get('resource', 'resource')} {row.get('action', 'modified')}",
                    'source_ip': row.get('source_ip', 'Unknown'),
                    'event_details': f"{row.get('action', 'Operation')} on {row.get('resource_name', 'unknown')}"
                })
        
        # After-hours cluster admin actions
        if 'timestamp' in row and is_after_hours(row['timestamp']):
            if 'action' in row and row['action'] in ['create', 'delete', 'update']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user', 'unknown'),
                    'alert_type': 'Kubernetes',
                    'severity': 'Medium',
                    'resource': f"K8s {row.get('resource', 'resource')}",
                    'description': f"After-hours K8s {row.get('action', 'operation')}",
                    'source_ip': row.get('source_ip', 'Unknown'),
                    'event_details': f"Action at {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                })
    
    return alerts

def detect_container_threats(container_logs):
    """Detect threats in container logs"""
    alerts = []
    
    if container_logs is None or container_logs.empty:
        return alerts
    
    # Rule: Container privilege escalation
    for _, row in container_logs.iterrows():
        if 'action' in row and 'exec' in str(row.get('action', '')).lower():
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user', 'unknown'),
                'alert_type': 'Container',
                'severity': 'High',
                'resource': 'Container runtime',
                'description': f"Container exec by user {row.get('user', 'unknown')}",
                'source_ip': 'N/A',
                'event_details': f"Container ID: {row.get('container_id', 'unknown')}"
            })
        
        # Rule: Suspicious container image
        if 'image' in row and any(term in str(row.get('image', '')).lower() 
                              for term in ['alpine', 'busybox', 'debug', 'test']):
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user', 'unknown'),
                'alert_type': 'Container',
                'severity': 'Medium',
                'resource': 'Container image',
                'description': f"Suspicious container image used: {row.get('image', 'unknown')}",
                'source_ip': 'N/A',
                'event_details': f"Action: {row.get('action', 'unknown')}"
            })
    
    return alerts

def detect_network_threats(network_logs):
    """Detect threats in network logs"""
    alerts = []
    
    if network_logs is None or network_logs.empty:
        return alerts
    
    # Rule: Unusual ports
    suspicious_ports = [22, 23, 445, 3389, 4444, 5555, 8080, 8888]
    
    for _, row in network_logs.iterrows():
        # External IP communication
        if 'source_ip' in row and is_external_ip(row['source_ip']):
            alerts.append({
                'timestamp': row['timestamp'],
                'username': 'N/A',
                'alert_type': 'Network',
                'severity': 'Medium',
                'resource': 'Network communication',
                'description': f"Communication from external IP {row.get('source_ip', 'unknown')}",
                'source_ip': row.get('source_ip', 'Unknown'),
                'event_details': f"To destination {row.get('destination_ip', 'unknown')}"
            })
        
        # Suspicious port activity
        if 'port' in row and row['port'] in suspicious_ports:
            alerts.append({
                'timestamp': row['timestamp'],
                'username': 'N/A',
                'alert_type': 'Network',
                'severity': 'High',
                'resource': 'Network port',
                'description': f"Activity on suspicious port {row.get('port', 'unknown')}",
                'source_ip': row.get('source_ip', 'Unknown'),
                'event_details': f"Protocol: {row.get('protocol', 'unknown')}"
            })
        
        # Large data transfer
        if 'bytes' in row and row['bytes'] > 10000000:  # 10MB
            alerts.append({
                'timestamp': row['timestamp'],
                'username': 'N/A',
                'alert_type': 'Network',
                'severity': 'Medium',
                'resource': 'Data transfer',
                'description': f"Large data transfer: {row['bytes']/1000000:.2f} MB",
                'source_ip': row.get('source_ip', 'Unknown'),
                'event_details': f"To destination {row.get('destination_ip', 'unknown')}"
            })
    
    return alerts

def detect_cicd_threats(cicd_logs):
    """Detect threats in CI/CD pipeline logs"""
    alerts = []
    
    if cicd_logs is None or cicd_logs.empty:
        return alerts
    
    # Rule: Pipeline changes after hours
    for _, row in cicd_logs.iterrows():
        if 'timestamp' in row and is_after_hours(row['timestamp']):
            if 'event_type' in row and row['event_type'] in ['pipeline_modified', 'config_changed']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user', 'unknown'),
                    'alert_type': 'CI/CD',
                    'severity': 'High',
                    'resource': 'Pipeline configuration',
                    'description': f"After-hours pipeline changes by {row.get('user', 'unknown')}",
                    'source_ip': 'N/A',
                    'event_details': f"Pipeline: {row.get('pipeline_id', 'unknown')}"
                })
        
        # Rule: Pipeline failure
        if 'status' in row and row['status'] == 'failed':
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user', 'unknown'),
                'alert_type': 'CI/CD',
                'severity': 'Low',
                'resource': 'Pipeline execution',
                'description': f"Pipeline execution failed",
                'source_ip': 'N/A',
                'event_details': f"Pipeline: {row.get('pipeline_id', 'unknown')}, Repository: {row.get('repository', 'unknown')}"
            })
        
        # Rule: Master/main branch changes
        if 'branch' in row and row['branch'] in ['master', 'main']:
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user', 'unknown'),
                'alert_type': 'CI/CD',
                'severity': 'Medium',
                'resource': 'Main branch',
                'description': f"Changes to {row.get('branch', 'main')} branch",
                'source_ip': 'N/A',
                'event_details': f"Repository: {row.get('repository', 'unknown')}"
            })
    
    return alerts

def detect_system_threats(system_logs):
    """Detect threats in system logs"""
    alerts = []
    
    if system_logs is None or system_logs.empty:
        return alerts
    
    # Rule: Sudo or privilege escalation
    suspicious_terms = ['sudo', 'su ', 'privilege', 'permission', 'root', 'administrator', 'admin']
    error_terms = ['error', 'failed', 'denied', 'unauthorized', 'invalid']
    
    for _, row in system_logs.iterrows():
        # Look for privilege escalation
        if 'message' in row and any(term in str(row.get('message', '')).lower() for term in suspicious_terms):
            alerts.append({
                'timestamp': row['timestamp'],
                'username': row.get('user', 'unknown'),
                'alert_type': 'System',
                'severity': 'High',
                'resource': 'Operating system',
                'description': f"Potential privilege escalation by {row.get('user', 'unknown')}",
                'source_ip': 'N/A',
                'event_details': f"Process: {row.get('process', 'unknown')}"
            })
        
        # Look for system errors
        if 'message' in row and any(term in str(row.get('message', '')).lower() for term in error_terms):
            if 'log_level' in row and row['log_level'] in ['ERROR', 'CRITICAL', 'FATAL', 'WARNING']:
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user', 'unknown'),
                    'alert_type': 'System',
                    'severity': 'Medium',
                    'resource': 'System logs',
                    'description': f"{row.get('log_level', 'Error')} in system logs",
                    'source_ip': 'N/A',
                    'event_details': row.get('message', 'Unknown error')[:100]  # Truncate long messages
                })
        
        # After-hours system activity
        if 'timestamp' in row and is_after_hours(row['timestamp']):
            if 'user' in row and row['user'] not in ['system', 'root']:  # Exclude system users
                alerts.append({
                    'timestamp': row['timestamp'],
                    'username': row.get('user', 'unknown'),
                    'alert_type': 'System',
                    'severity': 'Low',
                    'resource': 'Operating system',
                    'description': f"After-hours system activity by {row.get('user', 'unknown')}",
                    'source_ip': 'N/A',
                    'event_details': f"Process: {row.get('process', 'unknown')}"
                })
    
    return alerts