import threading
import time
import ipaddress
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext

import concurrent.futures
import os
import platform
import re
import subprocess
from tkinter import messagebox
from scapy.all import sniff, ARP, conf, ARP, Ether, srp
#import uploadtoCSV


MinerSearchingStarting = True 

seen_devices = set() 
new_devices = []  
lock = threading.Lock()  

# Load target network
with open("networkToScan.txt", "r") as f:
    thisIPNetwork = f.read().strip()

#makes sure that the range starts with the even number

TARGET_RANGE = ipaddress.ip_network(f"{thisIPNetwork}0/23", strict=False) #/23 for 512 addresses. /22 will scan 1024 addresses

# GUI Class
class DeviceSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("The Best Miner Sniffer Ever")
        self.root.geometry("700x700")

        tk.Label(root, text=f"New Devices Log for {thisIPNetwork}", font=("Arial", 11)).pack(anchor="w", padx=10,pady=(4,0))
        self.log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20, state="disabled")
        self.log_box.pack(pady=2)
        
        tk.Label(root, text="Command Prompt", font=("Arial", 11)).pack(anchor="w", padx=10,pady=(2,2))
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=10, state="disabled")
        self.text_area.pack(pady=(2,10))

        
        

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(side="left", padx=20)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", state="disabled")
        self.stop_button.pack(side="left", padx=20)

        self.skip_button = tk.Button(root, text="Skip Machine", command=self.skip_machine, bg="orange", fg="black")
        self.skip_button.pack(side="left", padx=20)

        self.scan_button = tk.Button(root, text="Intial Scan", command=self.initial_scan, bg="yellow", fg="black")
        self.scan_button.pack(side="left", padx = 20)

        #self.upload_button = tk.Button(root, text="CSV Upload", command=self.upload_devices_to_sheets, bg="purple", fg="black")
        #self.upload_button.pack(side="left", padx=20)

        self.refresh_button = tk.Button(root, text="Refresh Devices", command=self.display_devices, bg="blue", fg="white")
        self.refresh_button.pack(side="left", padx=20)


        self.quit_button = tk.Button(root, text="Quit", command=self.root.quit, bg="gray", fg="white")
        self.quit_button.pack(side="right", padx=20)



        self.root.bind("c", lambda e: self.key_response("c"))
        self.root.bind("s", lambda e: self.key_response("s"))
        self.user_choice = None

        self.sniffing = False
        self.totalDevices = 0

        # Load logs
        self.load_existing_logs()
        self.auto_refresh_devices()

    def key_response(self, choice):
        self.user_choice = choice
        #self.log(f"Key pressed: {choice.upper()}")

    def log(self, message):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.yview(tk.END)
        self.text_area.config(state="disabled")


        #135, 229, 240, 231, 217, 254, 206

    def load_existing_logs(self):
        try:
            with open("pre_existing_devices.txt", "r") as f:
                for line in f.readlines():
                    if line.strip():
                        seen_devices.add(normalize_ip(line.split('|')[1].strip()))
                        
            with open("new_devices_log.txt", "r") as f:
                for line in f.readlines():
                    if line.strip():
                        seen_devices.add(normalize_ip(line.split('|')[1].strip()))
                        segment = line.split('|')[1].strip().split('.')[2]
                        if ")" in segment:  
                            segment = segment.split(')')[0]  

                        segment_number = int(segment)
                        if segment_number %2 != 0:
                            segment_number -= 1


                        if (segment_number == int(thisIPNetwork.split('.')[2])):
                            self.totalDevices = max(self.totalDevices, int(line.split('|')[5].strip().replace('?', '')))
                        
        except FileNotFoundError:
            pass
        #print(f"seen devices: {seen_devices}")

        with open("new_devices_log.txt", "a+") as f:
            if f.tell() != 0:  
                f.seek(0, 2)  # go to the end of the file
                f.seek(f.tell() - 1, 0)  # move back 1 char
                last_char = f.read(1)
                if last_char != "\n":
                    f.write("\n")
            

    def display_devices(self):
        try:
            with open("new_devices_log.txt", "r") as f:
                content = f.read()
        except FileNotFoundError:
            content = "new_devices_log.txt not found."

        lineNumber = 1
        new_content = []
        for line in content.splitlines():
            new_content.append(f"|{lineNumber}|  {line}")
            lineNumber += 1

        # Join back into a string if needed
        edited_content = "\n".join(new_content)

        self.log_box.config(state="normal")   # enable editing temporarily
        self.log_box.delete('1.0', tk.END)    # clear previous contents
        self.log_box.insert(tk.END, edited_content)  # insert file content
        self.log_box.yview(tk.END)            # scroll to the bottom
        self.log_box.config(state="disabled") # make read-only again
   
    def auto_refresh_devices(self):
        self.display_devices()
        self.root.after(5000, self.auto_refresh_devices)  # refresh every 5 seconds

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.log("🔍 Listening for new devices... (reports every 5 seconds)")

            threading.Thread(target=self.report, daemon=True).start()
            threading.Thread(target=lambda: sniff(prn=self.arp_listening, filter="arp", store=0, stop_filter=lambda _: not self.sniffing), daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.log("⏹ Stopped sniffing.")

    def report(self):
        
        #missed = 0
        #interval_before_questioned = 3

        while self.sniffing:
            time.sleep(5)
            with lock:
                if new_devices:
                    

                    flag = False
                    if(len(new_devices) >= 2):
                        result = messagebox.askquestion("Question", "Multiple new devices found. Do you want to store ips and flag/superposition them?")
                        if result == "yes":
                            flag = True

                    for ip, mac in new_devices:
                        self.totalDevices += 1
                        msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New device: {ip}  MAC: {mac} Number: {self.totalDevices}"
                        self.log(msg)
                            
                        if flag:
                            with open("new_devices_log.txt", "a") as f:
                                f.write(f"IP: |{ip}| MAC: |{mac}| Number: |{self.totalDevices}?|\n")
                            self.totalDevices -= 1
                        if not flag:
                            with open("new_devices_log.txt", "a") as f:
                                f.write(f"IP: |{ip}| MAC: |{mac}| Number: |{self.totalDevices}|\n")

                    if flag:
                        self.totalDevices += 1
                        
                    
                    new_devices.clear()
                else:
                    self.log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No new devices found.")
                    
                    '''
                    missed += 1
                    if missed >= interval_before_questioned:
                        self.log("⚠️ No new devices found for a while. Press 'C' to continue or 'S' to skip.")
                        
                        while self.user_choice not in ("c", "s") and self.sniffing:
                            time.sleep(0.1)

                        if self.user_choice == "s":
                            self.totalDevices += 1
                            msg = f"Skipping Machine {self.totalDevices}."
                            self.log(msg)
                            
                            with open("new_devices_log.txt", "a") as f:
                                f.write(f"IP: |Skipped Machine ({thisIPNetwork})| MAC: |N/A| Number: |{self.totalDevices}|\n")
                            
                        missed = 0

                        self.user_choice = None   
                    '''

    def skip_machine(self):
        self.totalDevices += 1
        msg = f"Skipping Machine {self.totalDevices}."
        self.log(msg)
        with open("new_devices_log.txt", "a") as f:
            f.write(f"IP: |Skipped Machine ({thisIPNetwork})| MAC: |N/A| Number: |{self.totalDevices}|\n")
                            

    def arp_listening(self, pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):  
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            try:
                if ipaddress.ip_address(ip) in TARGET_RANGE:
                    with lock:
                        
                        if ip not in seen_devices:
                            seen_devices.add(normalize_ip(ip))
                            new_devices.append((ip, mac))
                            
            except ValueError:
                pass

    def initial_scan(self):
             
        
        active = self.ping_sweep_tosho(network_prefix=thisIPNetwork)
        #print("Active IPs:", active)
        self.log("Inital IP Scan Completed.")

        with open("pre_existing_devices.txt", "w") as f:
            for ip,mac in active:
                f.write(f"IP: |{ip}| MAC: |{mac}|\n")
        
        self.load_existing_logs()

    def ping_sweep_tosho(self, network_prefix, start=200, end=230, timeout=1):
        active_devices = []
        conf.verb = 0  
        self.log("Starting ping sweep...")
        

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor: #ong this parallelism is crazy
            future_to_ip = {executor.submit(ping, ip): ip for ip in TARGET_RANGE}

            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                results = future.result()
                if results:
                    for ip, mac, method in results:
                        self.log(f"{ip} is active, MAC: {mac} via {method}")
                        active_devices.append((ip, mac))


        return active_devices

    def upload_devices_to_sheets(self):
        #uploadtoCSV.upload_devices_to_sheets()
        self.log("CSV upload disabled.")

# Sniffer Function







def get_mac_from_arp(ip):
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.check_output(["arp", "-a", ip], text=True)
            match = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", output, re.I)
        else: #If using a macbook or linux
            output = subprocess.check_output(["arp", "-n", ip], text=True)
            match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", output, re.I)
        return match.group(1).replace("-", ":") if match else None
    except subprocess.CalledProcessError:
        return None

def wake_ping(ip):

    ip = str(ip)
    param = "-n" if platform.system().lower() == "windows" else "-c"
    null_dev = "nul" if platform.system().lower() == "windows" else "/dev/null"
    os.system(f"ping {param} 1 {ip} >{null_dev} 2>&1")

def normalize_ip(ip):

    if isinstance(ip, ipaddress.IPv4Address):
        ip = str(ip)

    if "Skipped Machine" in ip:
        return "Skipped Machine"
    return str(ipaddress.ip_address(str(ip).strip()))

def arp_ping(ip, timeout=2):
    arp = ARP(pdst = ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result = srp(packet, timeout=timeout, verbose=False)[0]
        if result:
            return [(rcv.psrc, rcv.hwsrc) for snd, rcv in result]
    except Exception:
        pass
    
    return []


def ping(ip, timeout=2):
    ip = normalize_ip(ip)

    wake_ping(ip)   
    mac = get_mac_from_arp(ip)
    method = "ping" if mac else "arp"
    
    if not mac:  
        arp_results = arp_ping(ip, timeout)
        if arp_results:
            #print(f"MAC address found via ARP for {ip}: {arp_results[0][1]}")
            return [(ip, mac, "arp") for ip, mac in arp_results]
    else:
        #print(f"MAC address found via ping for {ip}: {mac}")
        return [(ip, mac, method)]
    #print(f"No MAC address found for {ip} using ping or ARP.")
    return None


# Run GUI
if __name__ == "__main__":
    
    root = tk.Tk()
    app = DeviceSnifferGUI(root)
    root.mainloop()