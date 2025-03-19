#!/usr/bin/env python3

"""
NetCut GUI for Huawei LTE routers.

A graphical tool to view connected devices and block/unblock internet access
by manipulating the router's MAC address filter.

Usage:
  python netcut_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import socket
import subprocess
import platform
import re
from huawei_lte_api.Connection import Connection
from huawei_lte_api.AuthorizedConnection import AuthorizedConnection
from huawei_lte_api.Client import Client
from huawei_lte_api.api.WLan import WLan
from huawei_lte_api.exceptions import ResponseErrorException

class NetcutGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Huawei LTE NetCut")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        self.connection = None
        self.client = None
        self.wlan = None
        self.devices = []
        self.blocked_macs = set()
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", font=("Helvetica", 10))
        self.style.configure("TLabel", font=("Helvetica", 10))
        self.style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        self.style.configure("Badge.TLabel", font=("Helvetica", 10), background="#e0e0e0", padding=5, relief="solid", borderwidth=1)
        self.style.configure("BadgeEnabled.TLabel", background="#a8e6cf", foreground="#1b5e20", padding=5, relief="solid", borderwidth=1)
        self.style.configure("BadgeDisabled.TLabel", background="#f8d7da", foreground="#721c24", padding=5, relief="solid", borderwidth=1)
        self.style.configure("Action.TButton", padding=2, font=("Helvetica", 8))
        self.style.configure("Block.TButton", background="#f8d7da", foreground="#721c24")
        self.style.configure("Unblock.TButton", background="#a8e6cf", foreground="#1b5e20")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Router Connection", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)
        
        # URL row with detect button
        url_frame = ttk.Frame(conn_frame)
        url_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(url_frame, text="Router URL:").pack(side=tk.LEFT, padx=(0, 5))
        self.url_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.url_var, width=30).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(url_frame, text="Detect", command=self.detect_gateway, width=8).pack(side=tk.LEFT)
        
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar(value="admin")
        ttk.Entry(conn_frame, textvariable=self.username_var, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.password_var, show="*", width=30).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(conn_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", command=self.connect_to_router)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Filter status frame with badge
        self.filter_frame = ttk.LabelFrame(main_frame, text="MAC Filter Status", padding="10")
        self.filter_frame.pack(fill=tk.X, pady=5)
        
        filter_status_frame = ttk.Frame(self.filter_frame)
        filter_status_frame.pack(fill=tk.X, expand=True)
        
        self.filter_status_label = ttk.Label(filter_status_frame, text="Not connected", style="Badge.TLabel")
        self.filter_status_label.pack(side=tk.LEFT, pady=5, padx=5)
        
        self.toggle_filter_btn = ttk.Button(filter_status_frame, text="Toggle Filter", 
                                           command=self.toggle_filter, state=tk.DISABLED)
        self.toggle_filter_btn.pack(side=tk.RIGHT, pady=5, padx=5)
        
        # Devices frame
        devices_frame = ttk.LabelFrame(main_frame, text="Connected Devices", padding="10")
        devices_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create treeview for devices
        columns = ("hostname", "mac", "ip", "status", "action")
        self.tree = ttk.Treeview(devices_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define headings
        self.tree.heading("hostname", text="Device Name")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("status", text="Status")
        self.tree.heading("action", text="Action")
        
        # Define columns
        self.tree.column("hostname", width=150)
        self.tree.column("mac", width=150)
        self.tree.column("ip", width=120)
        self.tree.column("status", width=80)
        self.tree.column("action", width=80)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        self.refresh_btn = ttk.Button(action_frame, text="Refresh Devices", command=self.refresh_devices, state=tk.DISABLED)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Not connected")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def detect_gateway(self):
        """Detect the default gateway and populate the router URL field"""
        try:
            self.status_var.set("Detecting default gateway...")
            self.root.update_idletasks()
            
            gateway = None
            os_name = platform.system()
            
            if os_name == "Windows":
                # Windows method
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "Default Gateway" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            gateway = match.group(1)
                            break
            elif os_name == "Linux" or os_name == "Darwin":  # Linux or MacOS
                # Linux/MacOS method
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    gateway = match.group(1)
            
            if gateway:
                self.url_var.set(f"http://{gateway}/")
                self.status_var.set(f"Default gateway detected: {gateway}")
            else:
                self.status_var.set("Could not detect default gateway")
                
        except Exception as e:
            self.status_var.set(f"Error detecting gateway: {str(e)}")
    
    def toggle_filter(self):
        """Toggle the MAC filter on/off"""
        if not self.connection:
            return
            
        try:
            # Get current filter status
            filter_status = self.wlan.get_filter_status()
            # Toggle it
            if filter_status['enabled']:
                self.set_filter_mode(False, "blacklist")
            else:
                self.set_filter_mode(True, "blacklist")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle filter: {str(e)}")
        
    def connect_to_router(self):
        try:
            self.status_var.set("Connecting to router...")
            self.root.update_idletasks()
            
            url = self.url_var.get()
            username = self.username_var.get()
            password = self.password_var.get()
            
            # Validate inputs
            if not url:
                messagebox.showerror("Error", "Please enter the router URL")
                self.status_var.set("Not connected")
                return
                
            # Create connection
            try:
                self.connection = AuthorizedConnection(url, username=username, password=password)
                self.client = Client(self.connection)
                self.wlan = WLan(self.connection)
                
                # Enable buttons
                self.connect_btn.config(state=tk.DISABLED)
                self.disconnect_btn.config(state=tk.NORMAL)
                self.refresh_btn.config(state=tk.NORMAL)
                self.toggle_filter_btn.config(state=tk.NORMAL)
                
                # Start refresh thread
                self.refresh_thread = threading.Thread(target=self.auto_refresh, daemon=True)
                self.refresh_thread.start()
                
                self.status_var.set("Connected to " + url)
                self.refresh_devices()
                self.update_filter_status()
                
            except ResponseErrorException as e:
                messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
                self.status_var.set("Connection failed")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                self.status_var.set("Connection failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            self.status_var.set("Connection failed")
    
    def disconnect(self):
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            
            self.connection = None
            self.client = None
            self.wlan = None
            
            # Clear devices
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            # Update UI
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.refresh_btn.config(state=tk.DISABLED)
            self.toggle_filter_btn.config(state=tk.DISABLED)
            
            self.filter_status_label.config(text="Not connected", style="Badge.TLabel")
            self.status_var.set("Disconnected")
    
    def auto_refresh(self):
        while self.connection:
            time.sleep(30)  # Refresh every 30 seconds
            try:
                if self.connection:
                    self.root.after(0, self.refresh_devices)
                    self.root.after(0, self.update_filter_status)
            except:
                pass
    
    def refresh_devices(self):
        if not self.connection:
            return
            
        try:
            self.status_var.set("Refreshing devices...")
            self.root.update_idletasks()
            
            # Get connected devices
            host_list = self.wlan.host_list()
            
            # Get filtered devices to see which are blocked
            filtered_info = self.wlan.get_filtered_devices()
            
            # Extract blacklisted MAC addresses
            blocked_macs = set()
            for filter_info in filtered_info:
                if filter_info['filter_type'] == 'blacklist':
                    for device in filter_info['devices']:
                        blocked_macs.add(device['mac'].upper())
            
            self.blocked_macs = blocked_macs
            
            # Clear current tree
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Fill tree with devices
            if 'Hosts' in host_list and 'Host' in host_list['Hosts']:
                hosts = host_list['Hosts']['Host']
                if not isinstance(hosts, list):
                    hosts = [hosts]
                
                for host in hosts:
                    mac = host.get('MacAddress', '').upper()
                    hostname = host.get('HostName', 'Unknown')
                    ip = host.get('IpAddress', '')
                    
                    status = "Blocked" if mac in blocked_macs else "Active"
                    
                    # Insert item without the action button
                    item_id = self.tree.insert('', tk.END, values=(hostname, mac, ip, status, ""))
                    
                    # Create a frame for the button and add it to the treeview
                    self.add_action_button(item_id, mac, status == "Blocked")
            
            self.status_var.set(f"Found {len(self.tree.get_children())} devices")
            
        except Exception as e:
            self.status_var.set(f"Error refreshing devices: {str(e)}")
    
    def add_action_button(self, item_id, mac, is_blocked):
        """Add block/unblock button to a treeview item"""
        # The frame needs to be recreated each time
        frame = ttk.Frame(self.tree)
        
        # Create the appropriate button based on blocked status
        if is_blocked:
            btn = ttk.Button(frame, text="Unblock", width=10, 
                         command=lambda m=mac: self.unblock_device(m),
                         style="Action.TButton")
        else:
            btn = ttk.Button(frame, text="Block", width=10, 
                         command=lambda m=mac: self.block_device(m),
                         style="Action.TButton")
        
        btn.pack(padx=4, pady=2)
        
        # Use the frame to place the button in the treeview
        self.tree.set(item_id, column="action", value="")
        self.tree.item(item_id, tags=(item_id,))
        
        def on_item_visible(event):
            bbox = self.tree.bbox(item_id, column="action")
            if bbox:  # If item is visible
                frame.place(x=bbox[0], y=bbox[1], width=bbox[2], height=bbox[3])
            else:
                frame.place_forget()
        
        # Bind to events that might change visibility
        self.tree.bind("<<TreeviewOpen>>", on_item_visible)
        self.tree.bind("<<TreeviewSelect>>", on_item_visible)
        self.tree.bind("<Configure>", on_item_visible)
        self.tree.tag_bind(item_id, "<Visibility>", on_item_visible)
        
        # Initial placement
        bbox = self.tree.bbox(item_id, column="action")
        if bbox:
            frame.place(x=bbox[0], y=bbox[1], width=bbox[2], height=bbox[3])
    
    def block_device(self, mac):
        """Block a device by MAC address"""
        try:
            # Find the hostname for this MAC
            hostname = "Unknown"
            for item_id in self.tree.get_children():
                item_values = self.tree.item(item_id, 'values')
                if item_values[1] == mac:
                    hostname = item_values[0]
                    break
            
            self.status_var.set(f"Blocking {hostname}...")
            self.root.update_idletasks()
            
            # Get current blacklisted devices
            filtered_devices = self.wlan.get_filtered_devices()
            
            # Find the blacklist
            mac_list = []
            hostname_list = []
            
            for filter_info in filtered_devices:
                if filter_info['filter_type'] == 'blacklist':
                    for device in filter_info['devices']:
                        mac_list.append(device['mac'])
                        hostname_list.append(device['hostname'])
            
            # Add the new device if it's not already in the list
            if mac.upper() not in [m.upper() for m in mac_list]:
                mac_list.append(mac)
                hostname_list.append(hostname)
            
            # Update the blacklist
            response = self.wlan.filter_mac_addresses(
                mac_list=mac_list,
                hostname_list=hostname_list,
                filter_status='2'  # '2' for blacklist
            )
            
            # Update UI
            self.refresh_devices()
            self.status_var.set(f"Blocked {hostname}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block device: {str(e)}")
            self.status_var.set("Block operation failed")
    
    def unblock_device(self, mac):
        """Unblock a device by MAC address"""
        try:
            # Find the hostname for this MAC
            hostname = "Unknown"
            for item_id in self.tree.get_children():
                item_values = self.tree.item(item_id, 'values')
                if item_values[1] == mac:
                    hostname = item_values[0]
                    break
            
            self.status_var.set(f"Unblocking {hostname}...")
            self.root.update_idletasks()
            
            # Get current blacklisted devices
            filtered_devices = self.wlan.get_filtered_devices()
            
            # Find the blacklist and remove the device
            mac_list = []
            hostname_list = []
            
            for filter_info in filtered_devices:
                if filter_info['filter_type'] == 'blacklist':
                    for device in filter_info['devices']:
                        if device['mac'].upper() != mac.upper():
                            mac_list.append(device['mac'])
                            hostname_list.append(device['hostname'])
            
            # Update the blacklist
            response = self.wlan.filter_mac_addresses(
                mac_list=mac_list,
                hostname_list=hostname_list,
                filter_status='2'  # '2' for blacklist
            )
            
            # Update UI
            self.refresh_devices()
            self.status_var.set(f"Unblocked {hostname}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock device: {str(e)}")
            self.status_var.set("Unblock operation failed")
    
    def update_filter_status(self):
        if not self.connection:
            return
            
        try:
            filter_status = self.wlan.get_filter_status()
            
            if filter_status['enabled']:
                status_text = f"FILTER ENABLED ({filter_status['mode']})"
                self.filter_status_label.config(text=status_text, style="BadgeEnabled.TLabel")
                self.toggle_filter_btn.config(text="Disable Filter")
            else:
                status_text = "FILTER DISABLED"
                self.filter_status_label.config(text=status_text, style="BadgeDisabled.TLabel")
                self.toggle_filter_btn.config(text="Enable Filter")
            
        except Exception as e:
            self.filter_status_label.config(text=f"Error: {str(e)}", style="Badge.TLabel")
    
    def set_filter_mode(self, enabled, mode):
        if not self.connection:
            return
            
        try:
            self.status_var.set(f"{'Enabling' if enabled else 'Disabling'} MAC filter...")
            self.root.update_idletasks()
            
            # Get the current filtered devices
            filtered_devices = self.wlan.get_filtered_devices()
            
            # Prepare the filter settings
            filter_status = '2' if mode == 'blacklist' else '1'  # '2' for blacklist, '1' for whitelist
            
            # Extract current devices from the filter lists to preserve them
            mac_list = []
            hostname_list = []
            
            for filter_info in filtered_devices:
                if (mode == 'blacklist' and filter_info['filter_type'] == 'blacklist') or \
                   (mode == 'whitelist' and filter_info['filter_type'] == 'whitelist'):
                    for device in filter_info['devices']:
                        mac_list.append(device['mac'])
                        hostname_list.append(device['hostname'])
            
            # Set the filter with the updated status but keep the same devices
            if mac_list:
                response = self.wlan.filter_mac_addresses(
                    mac_list=mac_list,
                    hostname_list=hostname_list,
                    filter_status=filter_status
                )
            else:
                # If no devices, create an empty filter
                response = self.wlan.set_multi_macfilter_settings([{
                    'Index': '0',
                    'WifiMacFilterStatus': filter_status
                }])
            
            # Update UI
            self.update_filter_status()
            self.refresh_devices()
            
            self.status_var.set(f"MAC filter {'enabled' if enabled else 'disabled'}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update filter: {str(e)}")
            self.status_var.set("Filter update failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetcutGUI(root)
    root.mainloop()