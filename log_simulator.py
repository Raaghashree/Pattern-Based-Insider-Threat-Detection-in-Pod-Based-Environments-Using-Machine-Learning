#!/usr/bin/env python3
"""
Insider Threat Detection - Log Simulator

This module simulates real-time log activity by reading existing log files
and randomly selecting entries to simulate as "new" logs.
"""

import pandas as pd
import random
import time
from datetime import datetime, timedelta
import os

class LogSimulator:
    def __init__(self, data_dir="data"):
        """
        Initialize the log simulator
        
        Args:
            data_dir (str): Directory containing the log CSV files
        """
        self.data_dir = data_dir
        self.logs = {
            'kubernetes': None,
            'container': None,
            'network': None,
            'auth': None,
            'cicd': None,
            'system': None
        }
        
        # Load all log files
        self._load_logs()
        
        # Track what we've already "simulated"
        self.simulated_indices = {k: set() for k in self.logs.keys()}
        
    def _load_logs(self):
        """Load all log files from the data directory"""
        # Check if the data directory exists
        if not os.path.exists(self.data_dir):
            print(f"Data directory {self.data_dir} not found")
            return
        
        # Load kubernetes logs
        k8s_path = os.path.join(self.data_dir, "kubernetes_logs.csv")
        if os.path.exists(k8s_path):
            self.logs['kubernetes'] = pd.read_csv(k8s_path)
            if 'timestamp' in self.logs['kubernetes'].columns:
                self.logs['kubernetes']['timestamp'] = pd.to_datetime(self.logs['kubernetes']['timestamp'], format='ISO8601')
        
        # Load container logs
        container_path = os.path.join(self.data_dir, "container_logs.csv")
        if os.path.exists(container_path):
            self.logs['container'] = pd.read_csv(container_path)
            if 'timestamp' in self.logs['container'].columns:
                self.logs['container']['timestamp'] = pd.to_datetime(self.logs['container']['timestamp'], format='ISO8601')
        
        # Load network logs
        network_path = os.path.join(self.data_dir, "network_logs.csv")
        if os.path.exists(network_path):
            self.logs['network'] = pd.read_csv(network_path)
            if 'timestamp' in self.logs['network'].columns:
                self.logs['network']['timestamp'] = pd.to_datetime(self.logs['network']['timestamp'], format='ISO8601')
        
        # Load auth logs
        auth_path = os.path.join(self.data_dir, "authentication_logs.csv")
        if os.path.exists(auth_path):
            self.logs['auth'] = pd.read_csv(auth_path)
            if 'timestamp' in self.logs['auth'].columns:
                self.logs['auth']['timestamp'] = pd.to_datetime(self.logs['auth']['timestamp'], format='ISO8601')
        
        # Load CICD logs
        cicd_path = os.path.join(self.data_dir, "cicd_logs.csv")
        if os.path.exists(cicd_path):
            self.logs['cicd'] = pd.read_csv(cicd_path)
            if 'timestamp' in self.logs['cicd'].columns:
                self.logs['cicd']['timestamp'] = pd.to_datetime(self.logs['cicd']['timestamp'], format='ISO8601')
        
        # Load system logs
        system_path = os.path.join(self.data_dir, "system_logs.csv")
        if os.path.exists(system_path):
            self.logs['system'] = pd.read_csv(system_path)
            if 'timestamp' in self.logs['system'].columns:
                self.logs['system']['timestamp'] = pd.to_datetime(self.logs['system']['timestamp'], format='ISO8601')
    
    def simulate_batch(self, num_logs=3):
        """
        Simulate a batch of log events by randomly selecting entries from
        the existing log files and updating their timestamps
        
        Args:
            num_logs (int): Number of logs to simulate in this batch
            
        Returns:
            dict: Dictionary containing simulated logs for each type
        """
        simulated = {k: pd.DataFrame() for k in self.logs.keys()}
        now = datetime.now()
        
        # Choose log types randomly but with weighting
        log_types = random.choices(
            list(self.logs.keys()),
            weights=[3, 2, 4, 5, 1, 2],  # Auth and network logs are more common
            k=num_logs
        )
        
        for log_type in log_types:
            df = self.logs.get(log_type)
            if df is None or df.empty:
                continue
                
            # Choose a random row that hasn't been simulated yet
            available_indices = set(df.index) - self.simulated_indices[log_type]
            if not available_indices:
                # If all rows have been used, reset
                self.simulated_indices[log_type] = set()
                available_indices = set(df.index)
                
            index = random.choice(list(available_indices))
            self.simulated_indices[log_type].add(index)
            
            # Create a copy of the row with an updated timestamp
            row = df.loc[index].copy()
            
            # Create a DataFrame with the updated row
            simulated_df = pd.DataFrame([row])
            
            # Update the timestamp to "now" (for real-time simulation)
            if 'timestamp' in simulated_df.columns:
                # Add some jitter (-5 to +5 seconds)
                jitter = random.randint(-5, 5)
                simulated_df['timestamp'] = now + timedelta(seconds=jitter)
                
            simulated[log_type] = simulated_df
            
        return simulated
    
    def get_all_logs(self):
        """
        Get all the loaded logs
        
        Returns:
            dict: Dictionary containing all loaded logs
        """
        return self.logs