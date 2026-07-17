# Windows Advanced Security Monitor (EDR Layer)

An advanced, multi-threaded real-time Windows security monitor (EDR Layer) featuring YARA static signature analysis, active process tracking, and TCP network connection monitoring.

---

## Complete Installation & Setup Guide

Follow these steps to set up and run the Security Monitor on your system.

### Prerequisites
Make sure you have Python installed on your Windows system. If not, download and install it from [https://www.python.org/](https://www.python.org/)

### Step 1: Clone or Download the Project
Download the ZIP file of this repository and extract it, or run this command in your terminal:

git clone [https://github.com/nafiul-dev01/windows-security-monitor.git](https://github.com/nafiul-dev01/windows-security-monitor.git)

### Step 2: Install Required Libraries
Open your Command Prompt or PowerShell and install the necessary dependencies:

pip install psutil watchdog yara-python

### Step 3: Run as Administrator (Required)
Since this monitor interacts with system-level processes and network sockets, it must be executed with elevated privileges.

1. Search for PowerShell or Command Prompt in your Windows Search bar.
2. Right-click on it and select "Run as Administrator".
3. Navigate to the project folder using the cd command.
4. Run the security agent:

python windows-security-monitor.py

---

## How to Test the Monitor

To verify that the engines are working correctly in real-time:

1. Process Tracking: Open a new PowerShell window; you will instantly see a [CRITICAL] Suspicious shell spawned! alert on the monitor terminal.
2. YARA Scan: Create a dummy script file in your Downloads directory; the watchdog will automatically intercept and run a signature scan on it.
