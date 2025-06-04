import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import os
import subprocess
import time
import threading
from collections import Counter
import detector
import log_simulator

# Set page configuration (must be the first Streamlit command)
st.set_page_config(
    page_title="Insider Threat Detection - SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
    }
    .sub-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #1E3A8A;
    }
    .alert-high {
        background-color: rgba(255, 59, 48, 0.1);
        border-left: 5px solid #FF3B30;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    .alert-medium {
        background-color: rgba(255, 149, 0, 0.1);
        border-left: 5px solid #FF9500;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    .alert-low {
        background-color: rgba(52, 199, 89, 0.1);
        border-left: 5px solid #34C759;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    .stats-container {
        padding: 10px 15px;
        border-radius: 5px;
        background-color: #f8f9fa;
        margin-bottom: 20px;
    }
    .realtime-header {
        color: #1E3A8A;
        animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.3; }
        100% { opacity: 1; }
    }
    .event-label {
        font-weight: bold;
        margin-right: 10px;
    }
    .timestamp-label {
        color: #6c757d;
        font-size: 0.9rem;
    }
    .icon-title {
        display: flex;
        align-items: center;
        gap: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'last_detection_run' not in st.session_state:
    st.session_state.last_detection_run = datetime.now() - timedelta(minutes=10)
if 'simulator' not in st.session_state:
    st.session_state.simulator = log_simulator.LogSimulator()
if 'simulated_logs' not in st.session_state:
    st.session_state.simulated_logs = {}
if 'simulated_counter' not in st.session_state:
    st.session_state.simulated_counter = 0
if 'running_simulation' not in st.session_state:
    st.session_state.running_simulation = False
if 'all_logs_count' not in st.session_state:
    st.session_state.all_logs_count = 0

# Main header
st.markdown('<div class="icon-title"><h1 class="main-header">🛡️ Insider Threat Detection SIEM</h1></div>', unsafe_allow_html=True)
st.markdown("Enterprise-grade security monitoring for detecting insider threats across your systems.")

# Function to check if it's time to run detection and run it if needed
def check_and_run_detection():
    current_time = datetime.now()
    time_diff = current_time - st.session_state.last_detection_run
    
    if time_diff.total_seconds() >= 300:  # 5 minutes
        try:
            # Run the detection pipeline
            st.session_state.last_detection_run = current_time
            subprocess.Popen(["python", "run_pipeline.py"], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
            return True
        except Exception as e:
            st.error(f"Error running detection pipeline: {str(e)}")
            return False
    return False

# Display next detection time in sidebar
def display_next_detection_time():
    next_run = st.session_state.last_detection_run + timedelta(minutes=5)
    time_left = next_run - datetime.now()
    
    if time_left.total_seconds() > 0:
        mins, secs = divmod(int(time_left.total_seconds()), 60)
        st.sidebar.info(f"Next detection run in: {mins}m {secs}s")
    else:
        st.sidebar.info("Detection pipeline will run on next refresh")

# Load all log files with caching
@st.cache_data(ttl=60)  # Cache for 1 minute
def load_log_data():
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
        return logs, "Data directory not found. Please ensure the directory exists."
    
    try:
        # Load kubernetes logs
        k8s_path = os.path.join(data_dir, "kubernetes_logs.csv")
        if os.path.exists(k8s_path):
            logs['kubernetes'] = pd.read_csv(k8s_path)
            if 'timestamp' in logs['kubernetes'].columns:
                logs['kubernetes']['timestamp'] = pd.to_datetime(logs['kubernetes']['timestamp'], format='ISO8601')
        
        # Load container logs
        container_path = os.path.join(data_dir, "container_logs.csv")
        if os.path.exists(container_path):
            logs['container'] = pd.read_csv(container_path)
            if 'timestamp' in logs['container'].columns:
                logs['container']['timestamp'] = pd.to_datetime(logs['container']['timestamp'], format='ISO8601')
        
        # Load network logs
        network_path = os.path.join(data_dir, "network_logs.csv")
        if os.path.exists(network_path):
            logs['network'] = pd.read_csv(network_path)
            if 'timestamp' in logs['network'].columns:
                logs['network']['timestamp'] = pd.to_datetime(logs['network']['timestamp'], format='ISO8601')
        
        # Load auth logs
        auth_path = os.path.join(data_dir, "authentication_logs.csv")
        if os.path.exists(auth_path):
            logs['auth'] = pd.read_csv(auth_path)
            if 'timestamp' in logs['auth'].columns:
                logs['auth']['timestamp'] = pd.to_datetime(logs['auth']['timestamp'], format='ISO8601')
        
        # Load CICD logs
        cicd_path = os.path.join(data_dir, "cicd_logs.csv")
        if os.path.exists(cicd_path):
            logs['cicd'] = pd.read_csv(cicd_path)
            if 'timestamp' in logs['cicd'].columns:
                logs['cicd']['timestamp'] = pd.to_datetime(logs['cicd']['timestamp'], format='ISO8601')
        
        # Load system logs
        system_path = os.path.join(data_dir, "system_logs.csv")
        if os.path.exists(system_path):
            logs['system'] = pd.read_csv(system_path)
            if 'timestamp' in logs['system'].columns:
                logs['system']['timestamp'] = pd.to_datetime(logs['system']['timestamp'], format='ISO8601')
                
        # Calculate total log count
        total_count = sum(0 if df is None else len(df) for df in logs.values())
        st.session_state.all_logs_count = total_count
        
        return logs, None
        
    except Exception as e:
        return logs, f"Error loading log data: {str(e)}"

# Load alerts with caching
@st.cache_data(ttl=60)  # Cache for 1 minute
def load_alerts():
    try:
        alerts_path = os.path.join("data", "alerts.csv")
        if os.path.exists(alerts_path):
            alerts = pd.read_csv(alerts_path)
            if 'timestamp' in alerts.columns:
                # Use ISO8601 format for flexible timestamp parsing
                alerts['timestamp'] = pd.to_datetime(alerts['timestamp'], format='ISO8601')
            return alerts
        else:
            return pd.DataFrame()  # Return empty DataFrame if alerts.csv doesn't exist
    except Exception as e:
        st.error(f"Error loading alerts: {str(e)}")
        return pd.DataFrame()

# Get alert icon based on severity
def get_severity_icon(severity):
    if severity.lower() == 'high':
        return "🔴"
    elif severity.lower() == 'medium':
        return "🟠"
    else:  # Low or any other
        return "🟢"

# Format alert for display
def format_alert_message(alert):
    timestamp = alert.get('timestamp', datetime.now())
    username = alert.get('username', 'unknown')
    description = alert.get('description', 'Unknown alert')
    source_ip = alert.get('source_ip', 'N/A')
    severity = alert.get('severity', 'Low')
    
    icon = get_severity_icon(severity)
    
    message = f"{icon} {description}"
    details = f"User: {username}"
    if source_ip != 'N/A':
        details += f" | Source IP: {source_ip}"
        
    time_str = timestamp.strftime("%b %d, %Y at %H:%M:%S")
    
    return message, details, time_str, severity.lower()

# Helper function to format log display for real-time simulation
def format_log_entry(log_type, entry):
    timestamp = entry.get('timestamp', datetime.now()).strftime("%H:%M:%S")
    
    if log_type == 'auth':
        user = entry.get('user_id', 'unknown')
        action = entry.get('event_type', entry.get('action', 'login'))
        status = entry.get('status', 'unknown')
        ip = entry.get('source_ip', 'unknown')
        return f"[{timestamp}] Auth: User '{user}' {action} {status} from {ip}"
    
    elif log_type == 'kubernetes':
        user = entry.get('user', 'unknown')
        action = entry.get('action', 'unknown')
        resource = entry.get('resource', 'unknown')
        name = entry.get('resource_name', 'unknown')
        return f"[{timestamp}] K8s: User '{user}' {action} {resource} '{name}'"
    
    elif log_type == 'container':
        user = entry.get('user', 'unknown')
        action = entry.get('action', 'unknown')
        container = entry.get('container_id', 'unknown')
        return f"[{timestamp}] Container: User '{user}' {action} container '{container}'"
    
    elif log_type == 'network':
        src = entry.get('source_ip', 'unknown')
        dst = entry.get('destination_ip', 'unknown')
        port = entry.get('port', 'unknown')
        protocol = entry.get('protocol', 'unknown')
        return f"[{timestamp}] Network: {src} -> {dst}:{port} ({protocol})"
    
    elif log_type == 'cicd':
        user = entry.get('user', 'unknown')
        event = entry.get('event_type', 'unknown')
        repo = entry.get('repository', 'unknown')
        branch = entry.get('branch', 'unknown')
        return f"[{timestamp}] CI/CD: User '{user}' {event} on {repo}/{branch}"
    
    elif log_type == 'system':
        user = entry.get('user', 'unknown')
        level = entry.get('log_level', 'INFO')
        process = entry.get('process', 'unknown')
        msg = entry.get('message', 'unknown')
        return f"[{timestamp}] System: [{level}] {process} - {msg} (User: {user})"
    
    else:
        return f"[{timestamp}] {log_type.capitalize()}: {entry}"

# Run threat detection on all logs
def detect_threats(logs):
    return detector.detect_threats(logs)

# Get most active users based on alerts
def get_most_active_users(alerts, num_users=5):
    if alerts.empty or 'username' not in alerts.columns:
        return []
    
    user_counts = alerts['username'].value_counts().head(num_users)
    return [{"username": user, "count": count} for user, count in user_counts.items()]

# Show alert details
def display_alert_details(alert):
    severity_class = f"alert-{alert.get('severity', 'low').lower()}"
    
    message, details, time_str, _ = format_alert_message(alert)
    
    alert_html = f"""
    <div class="{severity_class}">
        <div><strong>{message}</strong></div>
        <div>{details}</div>
        <div class="timestamp-label">{time_str}</div>
        <div><em>{alert.get('event_details', '')}</em></div>
    </div>
    """
    return st.markdown(alert_html, unsafe_allow_html=True)

# Helper function to display logs in a dataframe
def display_logs(df, log_type):
    if df is not None and not df.empty:
        # Sort by timestamp (most recent first) and take top 10
        df_sorted = df.sort_values(by='timestamp', ascending=False).head(10)
        
        # Select relevant columns based on log type
        columns_to_display = ['timestamp']
        
        # Add log-type specific columns
        if log_type == 'kubernetes':
            if 'user' in df_sorted.columns:
                columns_to_display.append('user')
            if 'action' in df_sorted.columns:
                columns_to_display.append('action')
            if 'resource' in df_sorted.columns:
                columns_to_display.append('resource')
            if 'resource_name' in df_sorted.columns:
                columns_to_display.append('resource_name')
            if 'status' in df_sorted.columns:
                columns_to_display.append('status')
            if 'source_ip' in df_sorted.columns:
                columns_to_display.append('source_ip')
        elif log_type == 'container':
            if 'container_id' in df_sorted.columns:
                columns_to_display.append('container_id')
            if 'action' in df_sorted.columns:
                columns_to_display.append('action')
            if 'user' in df_sorted.columns:
                columns_to_display.append('user')
            if 'status' in df_sorted.columns:
                columns_to_display.append('status')
            if 'image' in df_sorted.columns:
                columns_to_display.append('image')
        elif log_type == 'network':
            if 'source_ip' in df_sorted.columns:
                columns_to_display.append('source_ip')
            if 'destination_ip' in df_sorted.columns:
                columns_to_display.append('destination_ip')
            if 'protocol' in df_sorted.columns:
                columns_to_display.append('protocol')
            if 'port' in df_sorted.columns:
                columns_to_display.append('port')
            if 'bytes' in df_sorted.columns:
                columns_to_display.append('bytes')
            if 'action' in df_sorted.columns:
                columns_to_display.append('action')
        elif log_type == 'auth':
            if 'user_id' in df_sorted.columns:
                columns_to_display.append('user_id')
            if 'event_type' in df_sorted.columns:
                columns_to_display.append('event_type')
            if 'status' in df_sorted.columns:
                columns_to_display.append('status')
            if 'source_ip' in df_sorted.columns:
                columns_to_display.append('source_ip')
            if 'action' in df_sorted.columns:
                columns_to_display.append('action')
            if 'domain' in df_sorted.columns:
                columns_to_display.append('domain')
            if 'error_message' in df_sorted.columns and df_sorted['error_message'].notna().any():
                columns_to_display.append('error_message')
        elif log_type == 'cicd':
            if 'pipeline_id' in df_sorted.columns:
                columns_to_display.append('pipeline_id')
            if 'event_type' in df_sorted.columns:
                columns_to_display.append('event_type')
            if 'repository' in df_sorted.columns:
                columns_to_display.append('repository')
            if 'branch' in df_sorted.columns:
                columns_to_display.append('branch')
            if 'user' in df_sorted.columns:
                columns_to_display.append('user')
            if 'status' in df_sorted.columns:
                columns_to_display.append('status')
        elif log_type == 'system':
            if 'log_level' in df_sorted.columns:
                columns_to_display.append('log_level')
            if 'process' in df_sorted.columns:
                columns_to_display.append('process')
            if 'host' in df_sorted.columns:
                columns_to_display.append('host')
            if 'message' in df_sorted.columns:
                columns_to_display.append('message')
            if 'user' in df_sorted.columns:
                columns_to_display.append('user')
        
        # Filter columns that actually exist in the dataframe
        existing_columns = [col for col in columns_to_display if col in df_sorted.columns]
        
        # Display the dataframe
        st.dataframe(
            df_sorted[existing_columns],
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn(
                    "Timestamp",
                    format="MMM DD, YYYY, hh:mm:ss a",
                ),
                "bytes": st.column_config.NumberColumn(
                    "Bytes",
                    format="%d",
                ),
                "port": st.column_config.NumberColumn(
                    "Port",
                    format="%d",
                ),
            }
        )
    else:
        st.info(f"No {log_type} logs available.")

# Real-time log simulation
def start_simulation():
    realtime_container = st.empty()
    
    # Clear any previous simulated logs
    if 'simulated_logs' in st.session_state:
        st.session_state.simulated_logs = {}
    
    # Set the simulation flag to True
    st.session_state.running_simulation = True
    
    # Run simulation for a limited number of iterations or until user stops
    iteration = 0
    
    try:
        for iteration in range(30):  # Limited to 30 iterations to prevent infinite loops in Streamlit
            if not st.session_state.running_simulation:
                break
                
            # Simulate new logs
            new_logs = st.session_state.simulator.simulate_batch(num_logs=3)
            
            # Add to our simulated logs with timestamp keys
            timestamp = datetime.now()
            st.session_state.simulated_logs[timestamp] = new_logs
            st.session_state.simulated_counter += 1
            
            # Display the real-time feed
            with realtime_container.container():
                st.markdown("### 📊 Real-Time Log Stream")
                
                # Show the most recent logs (limited to last 10 timestamps)
                recent_times = sorted(st.session_state.simulated_logs.keys(), reverse=True)[:10]
                
                for ts in recent_times:
                    log_batch = st.session_state.simulated_logs[ts]
                    for log_type, df in log_batch.items():
                        if not df.empty:
                            # Format and display each log entry
                            log_entry = format_log_entry(log_type, df.iloc[0])
                            st.text(log_entry)
                
                # Run detection if we've collected enough logs
                if iteration > 0 and iteration % 5 == 0:
                    st.markdown("### 🔍 Running threat detection on collected logs...")
                    time.sleep(1)  # Simulate processing time
            
            # Sleep to simulate real-time updates
            time.sleep(1)
            
    except Exception as e:
        st.error(f"Simulation error: {str(e)}")
    finally:
        realtime_container.empty()
        st.session_state.running_simulation = False

# Stop simulation
def stop_simulation():
    st.session_state.running_simulation = False

# Run detection pipeline if needed
detection_ran = check_and_run_detection()

# Load the data
logs, error_message = load_log_data()
alerts = load_alerts()

# Show detection status if run
if detection_ran:
    st.success("Detection pipeline triggered. Results will be available soon.")

# We'll handle errors internally without displaying warnings to users

# Calculate metrics
total_alerts = 0
recent_alerts = 0
users_involved = set()
alert_types = Counter()

if not alerts.empty:
    total_alerts = len(alerts)
    
    # Recent alerts (last 24 hours)
    try:
        now = datetime.now()
        day_ago = now - timedelta(hours=24)
        recent_alerts = len(alerts[alerts['timestamp'] > day_ago])
    except Exception:
        # Silently handle exceptions and default to 0
        recent_alerts = 0
    
    # Users involved in alerts
    if 'username' in alerts.columns:
        users_involved = set(alerts['username'].unique())
    elif 'user_id' in alerts.columns:
        users_involved = set(alerts['user_id'].unique())
        
    # Count alert types
    if 'alert_type' in alerts.columns:
        alert_types = Counter(alerts['alert_type'])

# Create the metrics section
st.markdown('<h2 class="sub-header">📊 Security Dashboard Metrics</h2>', unsafe_allow_html=True)

# Metrics row
metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)

with metrics_col1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(label="Total Alerts", value=total_alerts)
    st.markdown('</div>', unsafe_allow_html=True)

with metrics_col2:
    # Calculate the total logs directly from the loaded data
    total_logs = sum(0 if df is None or df.empty else len(df) for df in logs.values())
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(label="Total Logs", value=f"{total_logs:,}")
    st.markdown('</div>', unsafe_allow_html=True)

with metrics_col3:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(label="Users Involved", value=len(users_involved))
    st.markdown('</div>', unsafe_allow_html=True)

with metrics_col4:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(label="Alert Types", value=len(alert_types))
    st.markdown('</div>', unsafe_allow_html=True)

# Create a two-column layout for alerts and visualizations
col1, col2 = st.columns([2, 1])

# Recent alerts and visualizations in the left column
with col1:
    # Display recent alerts
    st.markdown('<h2 class="sub-header">🚨 Recent Alert Feed</h2>', unsafe_allow_html=True)
    
    if not alerts.empty:
        # Sort by timestamp (most recent first) and take top 5
        recent_alerts_df = alerts.sort_values(by='timestamp', ascending=False).head(5)
        
        # Display each alert in a card
        for _, alert in recent_alerts_df.iterrows():
            display_alert_details(alert)
    else:
        st.info("No alerts available.")
        
    # Show alert trends visualization
    st.markdown('<h2 class="sub-header">📈 Alert Visualization</h2>', unsafe_allow_html=True)
    
    if not alerts.empty and 'timestamp' in alerts.columns:
        # Extract hour from timestamp
        alerts_with_hour = alerts.copy()
        alerts_with_hour['hour'] = alerts_with_hour['timestamp'].dt.hour
        
        # Create hour of day heatmap
        hour_counts = alerts_with_hour.groupby('hour').size().reset_index(name='count')
        
        # Create a 24-hour range for full display
        all_hours = pd.DataFrame({'hour': range(24)})
        hour_counts = pd.merge(all_hours, hour_counts, on='hour', how='left').fillna(0)
        
        fig = px.bar(
            hour_counts,
            x='hour',
            y='count',
            labels={'count': 'Number of Alerts', 'hour': 'Hour of Day (24h)'},
            height=300
        )
        
        fig.update_layout(
            title='Alerts by Hour of Day',
            xaxis_title='Hour (0-23)',
            yaxis_title='Alert Count',
            xaxis=dict(tickmode='linear', tick0=0, dtick=1),
            plot_bgcolor='rgba(0,0,0,0)',
            bargap=0.1
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Alert types breakdown
        if 'alert_type' in alerts.columns:
            alert_type_counts = alerts['alert_type'].value_counts().reset_index()
            alert_type_counts.columns = ['alert_type', 'count']
            
            fig = px.pie(
                alert_type_counts,
                values='count',
                names='alert_type',
                title='Alerts by Type',
                height=300
            )
            
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(
                showlegend=False,
                plot_bgcolor='rgba(0,0,0,0)'
            )
            
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert data available for visualization.")

# User activity and real-time feed in the right column
with col2:
    # Top users with alerts
    st.markdown('<h2 class="sub-header">👤 Top Users with Alerts</h2>', unsafe_allow_html=True)
    
    user_list = get_most_active_users(alerts)
    if user_list:
        user_text = ""
        for i, user_data in enumerate(user_list, 1):
            user_text += f"<div class='stats-container'><b>{i}. {user_data['username']}</b> - {user_data['count']} alerts</div>"
        
        st.markdown(user_text, unsafe_allow_html=True)
    else:
        st.info("No user alert data available.")
    
    # Real-time log simulation
    st.markdown('<h2 class="sub-header realtime-header">🔴 LIVE: Real-Time Log Stream</h2>', unsafe_allow_html=True)
    
    if not st.session_state.running_simulation:
        if st.button("Start Real-Time Simulation"):
            # Start the simulation in a separate thread
            simulation_thread = threading.Thread(target=start_simulation)
            simulation_thread.daemon = True
            simulation_thread.start()
    else:
        if st.button("Stop Simulation"):
            stop_simulation()
    
    # Display simulation status
    if st.session_state.simulated_counter > 0:
        st.info(f"Simulated {st.session_state.simulated_counter} log batches")

# Create tabs for log details
st.markdown('<h2 class="sub-header">📋 Log Details</h2>', unsafe_allow_html=True)
tabs = st.tabs(["Alerts", "Kubernetes", "Container", "Network", "Auth", "CI/CD", "System"])

# Alerts tab (first tab)
with tabs[0]:
    st.subheader("Alert Details")
    if not alerts.empty:
        # Add severity color coding
        if 'severity' in alerts.columns:
            alerts_sorted = alerts.sort_values(by=['timestamp'], ascending=False)
            
            # Custom formatting for alerts table
            st.dataframe(
                alerts_sorted,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn(
                        "Timestamp",
                        format="MMM DD, YYYY, hh:mm:ss a",
                    ),
                    "severity": st.column_config.Column(
                        "Severity",
                        help="Alert severity level",
                        width="small",
                    ),
                    "description": st.column_config.Column(
                        "Description",
                        width="large",
                    )
                }
            )
        else:
            st.dataframe(
                alerts.sort_values(by=['timestamp'], ascending=False),
                use_container_width=True,
                hide_index=True
            )
    else:
        st.info("No alerts available.")

# Kubernetes logs tab
with tabs[1]:
    st.subheader("Kubernetes Activity Logs")
    display_logs(logs['kubernetes'], 'kubernetes')

# Container logs tab
with tabs[2]:
    st.subheader("Container Activity Logs")
    display_logs(logs['container'], 'container')

# Network logs tab
with tabs[3]:
    st.subheader("Network Activity Logs")
    display_logs(logs['network'], 'network')

# Auth logs tab
with tabs[4]:
    st.subheader("Authentication Logs")
    display_logs(logs['auth'], 'auth')

# CICD logs tab
with tabs[5]:
    st.subheader("CI/CD Pipeline Logs")
    display_logs(logs['cicd'], 'cicd')

# System logs tab
with tabs[6]:
    st.subheader("System Logs")
    display_logs(logs['system'], 'system')

# Sidebar content
st.sidebar.title("🛡️ SIEM Controls")
st.sidebar.markdown("---")

# Display next detection run time
display_next_detection_time()

# Add manual detection button
if st.sidebar.button("📊 Run Threat Detection"):
    with st.spinner("Running detection pipeline..."):
        try:
            subprocess.run(["python", "run_pipeline.py"], check=True)
            st.session_state.last_detection_run = datetime.now()
            st.sidebar.success("Detection completed successfully!")
            # Force a rerun to show updated alerts
            st.rerun()
        except subprocess.CalledProcessError as e:
            st.sidebar.error(f"Error: {str(e)}")
        except Exception as e:
            st.sidebar.error(f"Unexpected error: {str(e)}")

# Add sidebar filter controls
st.sidebar.markdown("## 🔍 Filter Controls")

# Filter by severity if alerts have severity
if not alerts.empty and 'severity' in alerts.columns:
    severities = ['All'] + sorted(alerts['severity'].unique().tolist())
    selected_severity = st.sidebar.selectbox("Alert Severity", severities)
    
    if selected_severity != 'All':
        filtered_count = len(alerts[alerts['severity'] == selected_severity])
        st.sidebar.info(f"{filtered_count} {selected_severity} severity alerts")

# Filter by date range
st.sidebar.markdown("### 📅 Date Range")
if not alerts.empty and 'timestamp' in alerts.columns:
    min_date = alerts['timestamp'].min().date()
    max_date = alerts['timestamp'].max().date()
    
    date_range = st.sidebar.date_input(
        "Select date range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    if len(date_range) == 2:
        start_date, end_date = date_range
        st.sidebar.info(f"Selected: {start_date} to {end_date}")

# Show last refresh time
st.sidebar.markdown("---")
st.sidebar.text(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")