# NetworkTrafficAnalyzer
**Overview:**

The Network Traffic Analyzer is a Python-based tool designed to monitor and analyze network traffic for suspicious activities. It leverages the capabilities of Scapy library to capture and dissect network packets in real-time. This tool helps in identifying potential security threats such as unauthorized access attempts, suspicious IP addresses, and unusual traffic patterns.
**Features:**

    Real-time Traffic Analysis: Captures and analyzes network traffic in real-time.
    Suspicious Activity Detection: Detects and notifies about suspicious activities such as blacklisted IP addresses, unusual traffic behavior, etc.
    Geo-location Information: Fetches geo-location information for suspicious IP addresses using the IPInfo API.
    Notification Alerts: Provides notification alerts for detected suspicious activities.
    Report Generation: Generates a detailed report containing information about suspicious IP addresses, their geo-locations, and traffic flow.

**Usage:**

    **Installation:**
        Clone the repository to your local machine.
        Install the required dependencies by running pip install -r requirements.txt.

    Configuration:
        Customize the configuration by editing the config.yaml file. Specify blacklisted IP addresses and API keys as required.

    Run:
        Execute the script network_traffic_analyzer.py.
        Follow the on-screen instructions to start the analysis.

**Requirements:**

    Python 3.x
    Scapy
    Requests
    PyYAML
    Platform-specific modules (e.g., win10toast for Windows notification)

