#!/usr/bin/env python3
"""
Insider Threat Detection - Realtime Log Feeder

This script simulates real-time log updates from various sources.
It's used to feed logs into the system to demonstrate real-time monitoring.
"""

import os
import pandas as pd
import time
from datetime import datetime, timedelta
import random

def update_logs():
    """
    Update log files with new entries to simulate real-time data feeds
    """
    print(f"[{datetime.now()}] Updating logs with new entries")
    
    # In a real system, this would pull data from actual log sources
    # For the demo, we'll just add a timestamp to show it's running
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"[{timestamp}] Log update complete")

if __name__ == "__main__":
    # Run in a loop to simulate continuous updates
    try:
        while True:
            update_logs()
            # Wait a few seconds between updates
            time.sleep(5)
    except KeyboardInterrupt:
        print("Log feeder stopped.")