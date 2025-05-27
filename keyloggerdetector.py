import psutil
import logging
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk
import requests
import time
import threading
import hashlib
import os
import json

print(">>>Keylogger Detector scipt has started<<<")

# Configure logging
logging.basicConfig(filename='suspicious_processes.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# List of known keylogger processes (this is not exhaustive)
suspicious_processes = [
    "keylogger",
    "logger",
    "capture",
    "spy",
    "monitor",
    "stealer",
    "recorder",
    "keycaptor",
    "keytrace",
    "inputlogger",
    "keylogger.exe",
    "keylogger.py"
]

# VirusTotal API key (replace with your own)
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTOAL_API_KEY'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'

#UPDATE URL (For version check)
GITHUB_REPO = 'https://api.github.com/repos/anshika-techie/final-phase-pbl/releases/latest'

class KeyloggerDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(">>--KEYLOGGER DETECTOR--<<")
        self.root.geometry("600x600")
        self.root.configure(bg="#f8f8f8")

        # Initialize scheduled_scan attribute
        self.scheduled_scan = False  # Initialize the attribute

        self.label = tk.Label(root, text="LET'S CHECK FOR DANGER", font=("Arial", 16), bg="#f8f8f8", fg="black")
        self.label.pack(pady=10)

        # Frame for scan button and close button
        self.scan_frame = tk.Frame(root, bg="#f8f8f8")
        self.scan_frame.pack(pady=10)

        self.scan_button = tk.Button(self.scan_frame, text=">> RUN SCAN", command=self.scan_processes, font=("Arial", 12), bg="#cce5cc", fg="black")
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.close_button = tk.Button(self.scan_frame, text=">> CLOSE TOOL", command=self.close_tool, font=("Arial", 12), bg="#f4cccc", fg="black")
        self.close_button.pack(side=tk.RIGHT, padx=5)

        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=10)

        self.result_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15, font=("Arial", 10), bg="#fdfdfd", fg="black")
        self.result_area.pack(pady=10)

        # Frame for buttons
        self.button_frame = tk.Frame(root, bg="#f8f8f8")
        self.button_frame.pack(pady=10)

        self.update_button = tk.Button(self.button_frame, text="> CHECK FOR UPDATE", command=self.check_for_updates, font=("Arial", 12), bg="#ffe0b2", fg="black")
        self.update_button.pack(side=tk.LEFT, padx=5)

        self.export_button = tk.Button(self.button_frame, text="> EXPORT RESULT", command=self.export_results, font=("Arial", 12), bg="#bbdefb", fg="black")
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.settings_button = tk.Button(self.button_frame, text="> CUSTOM SCAN", command=self.open_settings, font=("Arial", 12), bg="#ffe0b2", fg="black")
        self.settings_button.pack(side=tk.LEFT, padx=5)

        self.education_button = tk.Button(root, text=">> KEYLOGGER INFO", command=self.show_education, font=("Arial", 12), bg="#ffe0b2", fg="black")
        self.education_button.pack(pady=10)

        # Start a thread for real-time monitoring
        self.monitor_thread = threading.Thread(target=self.real_time_monitoring, daemon=True)
        self.monitor_thread.start()

    def get_system_processes(self):
        """Get a set of known system processes."""
        return {proc.name() for proc in psutil.process_iter()}

    def get_file_hash(self, file_path):
        """Calculate the MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return None
        return hash_md5.hexdigest()

    def check_virustotal(self, file_hash):
        """Check the file hash against VirusTotal."""
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(VIRUSTOTAL_URL + file_hash, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                result = f"Malicious file detected on VirusTotal: {file_hash}\n"
                self.result_area.insert(tk.END, result)
                logging.info(result.strip())

    def is_suspicious_behavior(self, proc):
        """Check for suspicious behavior based on heuristics."""
        try:
            if proc.num_fds() > 100:  # Arbitrary threshold for demonstration
                return True
            
            if proc.info['username'] in ['root', 'SYSTEM']:  # Example of suspicious users
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return False

    def scan_processes(self):
        """Scan for suspicious processes."""
        self.result_area.delete(1.0, tk.END)  # Clear previous results
        found_suspicious = False  # Flag to track if any suspicious process is found

        self.progress.start()  # Start the progress bar
        self.progress['value'] = 0  # Reset progress bar value
        system_processes = self.get_system_processes()  # Get system processes

        self.result_area.insert(tk.END, "Scanning for suspicious processes...\n")
        logging.info("Scanning for suspicious processes...")

        total_processes = len(psutil.pids())
        scanned_processes = 0

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
            scanned_processes += 1
            self.progress['value'] = (scanned_processes / total_processes) * 100  # Update progress bar

            # Update the UI to reflect the progress
            self.root.update_idletasks()

            try:
                # Display the process being scanned
                self.result_area.insert(tk.END, f"Scanning process: {proc.info['name']} (PID: {proc.info['pid']})\n")

                # Skip known system processes
                if proc.info['name'] in system_processes:
                    continue

                # Check process name and hash
                if any(suspicious in proc.info['name'].lower() for suspicious in suspicious_processes):
                    result = f"Suspicious process found: {proc.info['name']} (PID: {proc.info['pid']})\n"
                    self.result_area.insert(tk.END, result)
                    logging.info(result.strip())
                    found_suspicious = True
                    file_hash = self.get_file_hash(proc.info['exe'])
                    if file_hash:
                        self.check_virustotal(file_hash)  # Check the executable hash

                # Check command line arguments
                if any(suspicious in ' '.join(proc.info['cmdline']).lower() for suspicious in suspicious_processes):
                    result = f"Suspicious command line detected: {' '.join(proc.info['cmdline'])} (PID: {proc.info['pid']})\n"
                    self.result_area.insert(tk.END, result)
                    logging.info(result.strip())
                    found_suspicious = True
                    cmd_hash = self.get_file_hash(' '.join(proc.info['cmdline']))
                    if cmd_hash:
                        self.check_virustotal(cmd_hash)

                # Enhanced heuristic checks for suspicious behavior
                if self.is_suspicious_behavior(proc):
                    result = f"Suspicious behavior detected from: {proc.info['name']} (PID: {proc.info['pid']})\n"
                    self.result_area.insert(tk.END, result)
                    logging.info(result.strip())
                    found_suspicious = True

                # Automated response actions
                if found_suspicious:
                    self.prompt_user_action(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.progress.stop()  # Stop the progress bar

        if not found_suspicious:
            self.result_area.insert(tk.END, "No suspicious processes found.\n")
            logging.info("No suspicious processes found.")
        else:
            messagebox.showwarning("Warning", "Suspicious processes detected! Check the results.")

    def prompt_user_action(self, proc):
        """Prompt the user to take action on a suspicious process."""
        action = messagebox.askyesno("Suspicious Process Detected",
                                       f"Suspicious process {proc.info['name']} (PID: {proc.info['pid']}) detected. Do you want to terminate it?")
        if action:
            try:
                proc.terminate()  # Terminate the process
                self.result_area.insert(tk.END, f"Terminated process: {proc.info['name']} (PID: {proc.info['pid']})\n")
                logging.info(f"Terminated process: {proc.info['name']} (PID: {proc.info['pid']})")
            except Exception as e:
                messagebox.showerror("Error", f"Could not terminate process: {e}")

    def real_time_monitoring(self):
        """Monitor processes in real-time."""
        while True:
            if self.scheduled_scan:
                self.scan_processes()  # Call the scan processes method
            time.sleep(10)  # Check every 10 seconds

    def export_results(self):
        """Export the results to a text file."""
        if os.path.exists('suspicious_processes.log'):
            with open('suspicious_processes.log', 'r') as log_file:
                log_content = log_file.read()
            
            with open('exported_results.txt', 'w') as export_file:
                export_file.write(log_content)
            
            messagebox.showinfo("Export Results", "Results exported to 'exported_results.txt'.")
        else:
            messagebox.showerror("Export Results", "No log file found to export.")

    def open_settings(self):
        """Open settings to add new suspicious processes."""
        new_process = simpledialog.askstring("Settings", "Enter a new suspicious process name (comma-separated):")
        if new_process:
            new_processes = [proc.strip() for proc in new_process.split(',')]
            global suspicious_processes
            suspicious_processes.extend(new_processes)
            messagebox.showinfo("Settings", "Suspicious processes updated.")

    def check_for_updates(self):
        """Check for updates from the GitHub repository."""
        try:
            response = requests.get(GITHUB_REPO)
            if response.status_code == 200:
                latest_release = response.json()
                latest_version = latest_release['tag_name']
                current_version = "v1.0"  # Replace with your current version

                if latest_version != current_version:
                    messagebox.showinfo("Update Available", f"A new version {latest_version} is available!")
                else:
                    messagebox.showinfo("No Updates", "You are using the latest version.")
            else:
                messagebox.showerror("Error", "Could not check for updates.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while checking for updates: {e}")

    def schedule_scans(self):
        """Schedule scans at regular intervals."""
        interval = simpledialog.askinteger("Schedule Scan", "Enter scan interval in seconds:")
        if interval:
            self.scheduled_scan = True
            self.result_area.insert(tk.END, f"Scheduled scans every {interval} seconds.\n")
            logging.info(f"Scheduled scans every {interval} seconds.")
            threading.Thread(target=self.run_scheduled_scans, args=(interval,), daemon=True).start()

    def run_scheduled_scans(self, interval):
        """Run scheduled scans based on the specified interval."""
        while self.scheduled_scan:
            self.scan_processes()
            time.sleep(interval)

    def stop_scheduled_scans(self):
        """Stop scheduled scans."""
        self.scheduled_scan = False
        self.result_area.insert(tk.END, "Scheduled scans stopped.\n")
        logging.info("Scheduled scans stopped.")

    def show_education(self):
        """Show user education resources about keyloggers."""
        education_text = (
            "Keyloggers are malicious software designed to record keystrokes.\n"
            "Here are some tips to protect against keyloggers:\n"
            "1. Use antivirus software and keep it updated.\n"
            "2. Be cautious of suspicious emails and downloads.\n"
            "3. Use a firewall to monitor incoming and outgoing traffic.\n"
            "4. Regularly update your operating system and applications.\n"
            "5. Consider using a password manager to avoid typing passwords directly.\n"
        )
        messagebox.showinfo("User Education", education_text)

    def close_tool(self):
        """Close the application."""
        self.stop_scheduled_scans()  # Ensure scheduled scans are stopped
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()