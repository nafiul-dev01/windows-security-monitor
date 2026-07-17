import os
import sys
import time
import threading
import ctypes
from datetime import datetime
import psutil
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# 0. CONFIGURATION & YARA RULES
# ==========================================
# A sample in-memory YARA rule to detect suspicious scripts or PE files
YARA_RULES_SRC = """
rule Detect_Suspicious_Webshell_Or_Payload {
    meta:
        description = "Detects common hacking patterns in text/binary payloads"
        author = "Security Team"
    strings:
        $s1 = "eval(base64_decode" ascii wide nocase
        $s2 = "System.Net.WebClient" ascii wide nocase
        $s3 = "IEX (New-Object Net.WebClient)" ascii wide nocase
        $s4 = "Invoke-Expression" ascii wide nocase
        $s5 = "VirtualAlloc" ascii wide nocase
    condition:
        any of them
}
"""

LOG_LOCK = threading.Lock()

def log_alert(level: str, message: str):
    """Thread-safe logging with ANSI escape color codes."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_str = f"[{timestamp}] [{level}] {message}"
    
    with LOG_LOCK:
        if level == "CRITICAL":
            print(f"\033[91m{alert_str}\033[0m")  # Red
        elif level == "WARNING":
            print(f"\033[93m{alert_str}\033[0m")  # Yellow
        elif level == "SUCCESS":
            print(f"\033[92m{alert_str}\033[0m")  # Green
        else:
            print(f"\033[94m{alert_str}\033[0m")  # Blue

def check_admin_privileges() -> bool:
    """Verifies if the current process is running with elevated privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ==========================================
# 1. FILE SYSTEM ENGINE (Watchdog + YARA)
# ==========================================
class YARASecurityHandler(FileSystemEventHandler):
    def __init__(self, compiled_yara_rules):
        self.rules = compiled_yara_rules
        # Monitoring high-risk binaries
        self.suspicious_extensions = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.bin'}

    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        _, ext = os.path.splitext(file_path.lower())

        if ext in self.suspicious_extensions:
            log_alert("WARNING", f"File created in monitored space: {file_path}. Scanning...")
            self.scan_file(file_path)

    def scan_file(self, file_path: str):
        """Scans target files against compiled YARA signature rules."""
        try:
            # Prevent reading highly lock-protected system files
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                return

            # Skip massive files to prevent CPU spikes during scanning
            if os.path.getsize(file_path) > 50 * 1024 * 1024:  # 50 MB Limit
                log_alert("INFO", f"Skipped scanning {file_path} (File size exceeds 50MB limit).")
                return

            # Execute YARA scan
            matches = self.rules.match(file_path)
            if matches:
                for match in matches:
                    log_alert("CRITICAL", f"YARA DETECTED! Threat matching rule [{match.rule}] in file: {file_path}")
            else:
                log_alert("SUCCESS", f"Clean: File {file_path} passed signature analysis.")

        except yara.Error as ye:
            log_alert("WARNING", f"YARA scanning engine error for {file_path}: {str(ye)}")
        except PermissionError:
            # Catches issues when file is still locked by the system downloader
            time.sleep(0.5)
            try:
                matches = self.rules.match(file_path)
                if matches:
                    log_alert("CRITICAL", f"YARA DETECTED (Delayed Match): {file_path} matched [{matches[0].rule}]")
            except Exception:
                pass
        except Exception as e:
            log_alert("WARNING", f"Failed scanning {file_path}: {str(e)}")


def run_file_monitor(compiled_rules):
    user_profile = os.environ.get("USERPROFILE", "C:\\")
    monitored_paths = [
        os.path.join(user_profile, "Downloads"),
        os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"))
    ]

    observer = Observer()
    handler = YARASecurityHandler(compiled_rules)

    for path in monitored_paths:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            log_alert("INFO", f"File System Monitor active on path: {path}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# ==========================================
# 2. PROCESS WATCHDOG ENGINE
# ==========================================
def run_process_monitor():
    log_alert("INFO", "Process Watchdog engine initialized successfully.")
    known_pids = set()

    for proc in psutil.process_iter(['pid']):
        try:
            known_pids.add(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Living-off-the-land (LotL) binary names commonly exploited
    suspect_executables = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "regasm.exe"}

    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)

                    if pid not in known_pids:
                        name = proc.info['name']
                        cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else "N/A"
                        user = proc.info['username']

                        if name.lower() in suspect_executables:
                            log_alert("CRITICAL", f"Suspicious shell spawned! PID: {pid} | Name: {name} | Cmd: {cmdline} | User: {user}")
                        else:
                            log_alert("WARNING", f"New Process Spawned: {name} (PID: {pid})")

                        known_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Remove exited processes
            terminated_pids = known_pids - current_pids
            for pid in terminated_pids:
                known_pids.remove(pid)

            time.sleep(0.5)
        except Exception as e:
            log_alert("WARNING", f"Process Monitor error: {str(e)}")


# ==========================================
# 3. NETWORK CONNECTIONS ENGINE
# ==========================================
def run_network_monitor():
    log_alert("INFO", "Network Connection Monitor initialized successfully.")
    established_connections = set()
    
    # Common Reverse-Shell or abnormal default connection ports
    suspicious_ports = {4444, 1337, 8080, 8888, 31337, 9001}

    while True:
        try:
            connections = psutil.net_connections(kind='tcp')
            current_conn_keys = set()

            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    pid = conn.pid

                    conn_key = (laddr, raddr, pid)
                    current_conn_keys.add(conn_key)

                    if conn_key not in established_connections:
                        try:
                            proc_name = psutil.Process(pid).name() if pid else "System"
                        except Exception:
                            proc_name = "Unknown"

                        rport = conn.raddr.port if conn.raddr else None
                        if rport in suspicious_ports:
                            log_alert("CRITICAL", f"Connection to suspicious port! PID: {pid} ({proc_name}) -> Remote: {raddr}")
                        else:
                            log_alert("WARNING", f"New Socket: {proc_name} ({pid}) | Local: {laddr} --> Remote: {raddr}")

                        established_connections.add(conn_key)

            # Cleanup closed sockets
            established_connections = established_connections & current_conn_keys
            time.sleep(1.0)
        except Exception as e:
            log_alert("WARNING", f"Network Monitor error: {str(e)}")


# ==========================================
# 4. AGENT ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    os.system('color')  # Forces CMD/PowerShell to properly render ANSI colors
    print("=" * 70)
    print("      WINDOWS ENTERPRISE ADVANCED SECURITY MONITOR (EDR LAYER)  ")
    print("=" * 70)

    if not check_admin_privileges():
        log_alert("CRITICAL", "Access Denied: EDR Monitor requires elevated administrative privileges.")
        print("[!] Please execute your interpreter/terminal as 'Run as Administrator'.")
        sys.exit(1)

    # Initializing & Compiling YARA rules
    try:
        compiled_yara = yara.compile(source=YARA_RULES_SRC)
        log_alert("SUCCESS", "YARA Engine compiled successfully with local rules.")
    except Exception as e:
        log_alert("CRITICAL", f"YARA compilation failed: {str(e)}")
        sys.exit(1)

    # Spawn thread engines
    file_thread = threading.Thread(target=run_file_monitor, args=(compiled_yara,), daemon=True)
    process_thread = threading.Thread(target=run_process_monitor, daemon=True)
    network_thread = threading.Thread(target=run_network_monitor, daemon=True)

    file_thread.start()
    process_thread.start()
    network_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        log_alert("INFO", "Terminating EDR Agent. Systems are no longer protected.")