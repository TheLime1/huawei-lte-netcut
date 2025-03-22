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
        self.root.geometry("900x700")
        self.root.minsize(900, 700)
        
        self.connection = None
        self.client = None
        self.wlan = None
        self.devices = []
        self.filtered_devices = []
        self.blocked_macs = set()
        self.connected_action_buttons = {}  # Store references to block buttons
        self.filtered_action_buttons = {}   # Store references to unblock buttons
        
        # For annoy tab
        self.selected_devices = set()  # Store selected devices for annoy feature
        self.annoy_boxes = {}          # Store device boxes in annoy tab
        self.annoy_thread = None       # Thread for running annoy sequence
        self.stop_annoy = False        # Flag to stop annoy sequence
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", font=("Helvetica", 10))
        self.style.configure("TLabel", font=("Helvetica", 10))
        self.style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        self.style.configure("Badge.TLabel", font=("Helvetica", 10), background="#e0e0e0", padding=5, relief="solid", borderwidth=1)
        self.style.configure("BadgeEnabled.TLabel", background="#a8e6cf", foreground="#1b5e20", padding=5, relief="solid", borderwidth=1)
        self.style.configure("BadgeDisabled.TLabel", background="#f8d7da", foreground="#721c24", padding=5, relief="solid", borderwidth=1)
        self.style.configure("Block.TButton", padding=2, font=("Helvetica", 8))
        self.style.configure("Unblock.TButton", padding=2, font=("Helvetica", 8))
        self.style.configure("DeviceBox.TFrame", background="#e0e0e0", borderwidth=1, relief="raised")
        self.style.configure("DeviceBoxSelected.TFrame", background="#ff6b6b", borderwidth=1, relief="raised")
        self.style.configure("UnblockAll.TButton", padding=8, font=("Helvetica", 12, "bold"), background="#4CAF50", foreground="#ffffff")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Create root container with scrollbar
        root_container = ttk.Frame(self.root)
        root_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas with scrollbar for the entire content
        self.main_canvas = tk.Canvas(root_container)
        main_scrollbar = ttk.Scrollbar(root_container, orient=tk.VERTICAL, command=self.main_canvas.yview)
        self.main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Main frame inside canvas
        main_frame = ttk.Frame(self.main_canvas)
        self.main_canvas.create_window((0, 0), window=main_frame, anchor="nw", tags="main_frame")
        main_frame.bind("<Configure>", self.on_main_frame_configure)
        
        # Create horizontal container for connection and filter frames
        top_container = ttk.Frame(main_frame)
        top_container.pack(fill=tk.X, pady=5)
        
        # Connection frame - now placed in the left side of top_container
        conn_frame = ttk.LabelFrame(top_container, text="Router Connection", padding="10")
        conn_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # URL row with detect button
        url_frame = ttk.Frame(conn_frame)
        url_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(url_frame, text="Router URL:").pack(side=tk.LEFT, padx=(0, 5))
        self.url_var = tk.StringVar(value="http://192.168.8.1/")
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
        
        # Filter status frame with badge - now placed in the right side of top_container
        self.filter_frame = ttk.LabelFrame(top_container, text="MAC Filter Status", padding="10")
        self.filter_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        filter_status_frame = ttk.Frame(self.filter_frame)
        filter_status_frame.pack(fill=tk.X, expand=True)
        
        self.filter_status_label = ttk.Label(filter_status_frame, text="Not connected", style="Badge.TLabel")
        self.filter_status_label.pack(side=tk.LEFT, pady=5, padx=5)
        
        self.toggle_filter_btn = ttk.Button(filter_status_frame, text="Toggle Filter", 
                                           command=self.toggle_filter, state=tk.DISABLED)
        self.toggle_filter_btn.pack(side=tk.RIGHT, pady=5, padx=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Devices Tab - Contains both connected and filtered devices
        self.devices_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.devices_tab, text="Devices")
        
        # Annoy Them Tab
        self.annoy_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.annoy_tab, text="Annoy Them")
        
        # Setup content for Devices tab
        self.setup_devices_tab()
        
        # Setup content for Annoy Them tab
        self.setup_annoy_tab()
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        self.refresh_btn = ttk.Button(action_frame, text="Refresh Devices", command=self.refresh_all, state=tk.DISABLED)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Not connected")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def on_main_frame_configure(self, event):
        """Update the scroll region when the main frame changes size"""
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        # Set the canvas width to match its container
        self.main_canvas.itemconfig("main_frame", width=self.main_canvas.winfo_width())
    
    def setup_devices_tab(self):
        """Set up the Devices tab with connected and filtered devices"""
        # Connected Devices frame
        devices_frame = ttk.LabelFrame(self.devices_tab, text="Connected Devices", padding="10")
        devices_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a horizontal layout for treeview and buttons
        connected_devices_container = ttk.Frame(devices_frame)
        connected_devices_container.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for devices with updated column configuration (no action column)
        tree_frame = ttk.Frame(connected_devices_container)
        tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        columns = ("hostname", "mac", "ip", "status")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define headings
        self.tree.heading("hostname", text="Device Name")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("status", text="Status")
        
        # Define columns
        self.tree.column("hostname", width=150)
        self.tree.column("mac", width=150)
        self.tree.column("ip", width=120)
        self.tree.column("status", width=80)
        
        # Add scrollbars - vertical and horizontal
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=v_scrollbar.set, xscroll=h_scrollbar.set)
        
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add a frame for block buttons to the right of the treeview
        self.block_buttons_frame = ttk.Frame(connected_devices_container, width=100)
        self.block_buttons_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        # Filtered Devices frame
        filtered_frame = ttk.LabelFrame(self.devices_tab, text="Filtered/Blocked Devices", padding="10")
        filtered_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a horizontal layout for filtered treeview and buttons
        filtered_devices_container = ttk.Frame(filtered_frame)
        filtered_devices_container.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for filtered devices
        filtered_tree_frame = ttk.Frame(filtered_devices_container)
        filtered_tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        filtered_columns = ("hostname", "mac", "filter_type")
        self.filtered_tree = ttk.Treeview(filtered_tree_frame, columns=filtered_columns, show="headings", selectmode="browse")
        
        # Define headings for filtered devices
        self.filtered_tree.heading("hostname", text="Device Name")
        self.filtered_tree.heading("mac", text="MAC Address")
        self.filtered_tree.heading("filter_type", text="Filter Type")
        
        # Define columns for filtered devices
        self.filtered_tree.column("hostname", width=150)
        self.filtered_tree.column("mac", width=150)
        self.filtered_tree.column("filter_type", width=100)
        
        # Add scrollbars - vertical and horizontal
        v_filtered_scrollbar = ttk.Scrollbar(filtered_tree_frame, orient=tk.VERTICAL, command=self.filtered_tree.yview)
        h_filtered_scrollbar = ttk.Scrollbar(filtered_tree_frame, orient=tk.HORIZONTAL, command=self.filtered_tree.xview)
        self.filtered_tree.configure(yscroll=v_filtered_scrollbar.set, xscroll=h_filtered_scrollbar.set)
        
        v_filtered_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_filtered_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.filtered_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add a frame for unblock buttons to the right of the filtered treeview
        self.unblock_buttons_frame = ttk.Frame(filtered_devices_container, width=100)
        self.unblock_buttons_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
    
    def setup_annoy_tab(self):
        """Set up the Annoy Them tab with features for sequential blocking"""
        # Top part - Horizontal list of connected devices
        self.devices_list_frame = ttk.LabelFrame(self.annoy_tab, text="Select Devices to Annoy", padding="10")
        self.devices_list_frame.pack(fill=tk.X, expand=False, pady=5)
        
        # Scrollable frame for device boxes
        self.devices_canvas = tk.Canvas(self.devices_list_frame, height=120)
        scrollbar = ttk.Scrollbar(self.devices_list_frame, orient="horizontal", command=self.devices_canvas.xview)
        self.devices_canvas.configure(xscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.devices_canvas.pack(side=tk.TOP, fill=tk.X, expand=True)
        
        # Frame inside canvas for device boxes
        self.device_boxes_frame = ttk.Frame(self.devices_canvas)
        self.devices_canvas.create_window((0, 0), window=self.device_boxes_frame, anchor="nw")
        
        # Frame for Unblock All button
        unblock_frame = ttk.Frame(self.annoy_tab)
        unblock_frame.pack(fill=tk.X, pady=5)
        
        # Unblock All button
        self.unblock_all_btn = ttk.Button(unblock_frame, text="UNBLOCK ALL", 
                                         command=self.unblock_all_devices,
                                         style="UnblockAll.TButton", 
                                         state=tk.DISABLED)
        self.unblock_all_btn.pack(pady=5)
        
        # Paned window to split the bottom part
        self.annoy_paned = ttk.PanedWindow(self.annoy_tab, orient=tk.HORIZONTAL)
        self.annoy_paned.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left side (30%) - Monitoring tables
        monitor_frame = ttk.Frame(self.annoy_paned)
        self.annoy_paned.add(monitor_frame, weight=30)
        
        # Connected Devices monitoring table
        connected_monitor_frame = ttk.LabelFrame(monitor_frame, text="Connected Devices")
        connected_monitor_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Treeview with scrollbars for connected devices
        monitor_connected_frame = ttk.Frame(connected_monitor_frame)
        monitor_connected_frame.pack(fill=tk.BOTH, expand=True)
        
        # Simple treeview for connected devices (just names)
        columns = ("hostname",)
        self.monitor_connected_tree = ttk.Treeview(monitor_connected_frame, columns=columns, show="headings", selectmode="none")
        self.monitor_connected_tree.heading("hostname", text="Device Name")
        
        # Add scrollbars for the connected monitoring table
        v_monitor_connected_scrollbar = ttk.Scrollbar(monitor_connected_frame, orient=tk.VERTICAL, command=self.monitor_connected_tree.yview)
        h_monitor_connected_scrollbar = ttk.Scrollbar(monitor_connected_frame, orient=tk.HORIZONTAL, command=self.monitor_connected_tree.xview)
        self.monitor_connected_tree.configure(yscroll=v_monitor_connected_scrollbar.set, xscroll=h_monitor_connected_scrollbar.set)
        
        v_monitor_connected_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_monitor_connected_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.monitor_connected_tree.pack(fill=tk.BOTH, expand=True)
        
        # Blocked Devices monitoring table
        blocked_monitor_frame = ttk.LabelFrame(monitor_frame, text="Blocked Devices")
        blocked_monitor_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Treeview with scrollbars for blocked devices
        monitor_blocked_frame = ttk.Frame(blocked_monitor_frame)
        monitor_blocked_frame.pack(fill=tk.BOTH, expand=True)
        
        # Simple treeview for blocked devices (just names)
        columns = ("hostname",)
        self.monitor_blocked_tree = ttk.Treeview(monitor_blocked_frame, columns=columns, show="headings", selectmode="none")
        self.monitor_blocked_tree.heading("hostname", text="Device Name")
        
        # Add scrollbars for the blocked monitoring table
        v_monitor_blocked_scrollbar = ttk.Scrollbar(monitor_blocked_frame, orient=tk.VERTICAL, command=self.monitor_blocked_tree.yview)
        h_monitor_blocked_scrollbar = ttk.Scrollbar(monitor_blocked_frame, orient=tk.HORIZONTAL, command=self.monitor_blocked_tree.xview)
        self.monitor_blocked_tree.configure(yscroll=v_monitor_blocked_scrollbar.set, xscroll=h_monitor_blocked_scrollbar.set)
        
        v_monitor_blocked_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_monitor_blocked_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.monitor_blocked_tree.pack(fill=tk.BOTH, expand=True)
        
        # Right side (70%) - Annoyance methods
        methods_frame = ttk.Frame(self.annoy_paned)
        self.annoy_paned.add(methods_frame, weight=70)
        
        # Sequential blocking method
        sequential_frame = ttk.LabelFrame(methods_frame, text="Sequential Blocking")
        sequential_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Block time configuration
        time_frame = ttk.Frame(sequential_frame)
        time_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(time_frame, text="Block time (seconds):").pack(side=tk.LEFT, padx=(10, 5))
        self.block_time_var = tk.StringVar(value="10")
        ttk.Entry(time_frame, textvariable=self.block_time_var, width=10).pack(side=tk.LEFT)
        
        # Run and stop buttons
        button_frame = ttk.Frame(sequential_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.run_sequential_btn = ttk.Button(button_frame, text="Start Sequential Blocking", 
                                           command=self.start_sequential_blocking,
                                           state=tk.DISABLED)
        self.run_sequential_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_sequential_btn = ttk.Button(button_frame, text="Stop", 
                                            command=self.stop_sequential_blocking,
                                            state=tk.DISABLED)
        self.stop_sequential_btn.pack(side=tk.LEFT, padx=5)
        
        # Status of current operation
        self.annoy_status_frame = ttk.LabelFrame(sequential_frame, text="Status")
        self.annoy_status_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.annoy_status_var = tk.StringVar(value="Not running")
        self.annoy_status_label = ttk.Label(self.annoy_status_frame, textvariable=self.annoy_status_var, padding=10)
        self.annoy_status_label.pack(fill=tk.X)
        
        # Make the device boxes frame responsive to changes
        self.device_boxes_frame.bind("<Configure>", self.on_device_frame_configure)
    
    def on_device_frame_configure(self, event):
        """Update the scroll region when the device boxes frame changes size"""
        self.devices_canvas.configure(scrollregion=self.devices_canvas.bbox("all"))
    
    def toggle_device_selection(self, mac, hostname, box_frame):
        """Toggle selection of a device for annoying"""
        if mac in self.selected_devices:
            self.selected_devices.remove(mac)
            box_frame.configure(style="DeviceBox.TFrame")
        else:
            self.selected_devices.add(mac)
            box_frame.configure(style="DeviceBoxSelected.TFrame")
        
        # Enable/disable run button based on selection
        if self.selected_devices and self.connection:
            self.run_sequential_btn.configure(state=tk.NORMAL)
        else:
            self.run_sequential_btn.configure(state=tk.DISABLED)
    
    def start_sequential_blocking(self):
        """Start the sequential blocking process"""
        if not self.connection or not self.selected_devices:
            return
        
        try:
            # Get block time
            block_time = int(self.block_time_var.get())
            if block_time <= 0:
                messagebox.showerror("Error", "Block time must be greater than 0")
                return
                
            # Update UI
            self.run_sequential_btn.configure(state=tk.DISABLED)
            self.stop_sequential_btn.configure(state=tk.NORMAL)
            self.annoy_status_var.set("Starting sequential blocking...")
            
            # Reset stop flag
            self.stop_annoy = False
            
            # Start thread
            self.annoy_thread = threading.Thread(
                target=self.sequential_blocking_thread,
                args=(block_time,),
                daemon=True
            )
            self.annoy_thread.start()
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for block time")
            self.annoy_status_var.set("Error: Invalid block time")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sequential blocking: {str(e)}")
            self.annoy_status_var.set("Error starting sequential blocking")
    
    def sequential_blocking_thread(self, block_time):
        """Thread function for sequential blocking"""
        try:
            # Convert selected devices set to list for indexed access
            devices_to_annoy = []
            for mac in self.selected_devices:
                # Find hostname for this MAC
                for device_info in self.annoy_boxes.values():
                    if device_info['mac'] == mac:
                        devices_to_annoy.append({
                            'mac': mac,
                            'hostname': device_info['hostname']
                        })
                        break
            
            # Main loop - keep going until stopped
            while not self.stop_annoy and devices_to_annoy:
                for device in devices_to_annoy:
                    if self.stop_annoy:
                        break
                        
                    mac = device['mac']
                    hostname = device['hostname']
                    
                    # Update status
                    self.root.after(0, lambda m=hostname: self.annoy_status_var.set(f"Blocking {m} for {block_time} seconds"))
                    
                    # Block device
                    try:
                        self.block_device(mac, hostname)
                        
                        # Wait for block_time seconds, checking for stop flag periodically
                        elapsed = 0
                        while elapsed < block_time and not self.stop_annoy:
                            time.sleep(0.5)
                            elapsed += 0.5
                            # Update status with countdown
                            remaining = block_time - elapsed
                            if remaining > 0:
                                self.root.after(0, lambda m=hostname, r=int(remaining): 
                                                self.annoy_status_var.set(f"Blocking {m} for {r} more seconds"))
                        
                        # Unblock device if we didn't stop
                        if not self.stop_annoy:
                            self.unblock_device(mac, hostname)
                            
                            # Small pause between devices
                            for i in range(5):  # 2.5 second pause
                                if self.stop_annoy:
                                    break
                                time.sleep(0.5)
                    
                    except Exception as e:
                        self.root.after(0, lambda e=str(e): self.annoy_status_var.set(f"Error: {e}"))
            
            # Update status when done
            if self.stop_annoy:
                self.root.after(0, lambda: self.annoy_status_var.set("Sequential blocking stopped"))
            else:
                self.root.after(0, lambda: self.annoy_status_var.set("Sequential blocking completed"))
            
            # Reset UI
            self.root.after(0, self.reset_annoy_ui)
            
        except Exception as e:
            self.root.after(0, lambda e=str(e): self.annoy_status_var.set(f"Error: {e}"))
            self.root.after(0, self.reset_annoy_ui)
    
    def stop_sequential_blocking(self):
        """Stop the sequential blocking process"""
        self.stop_annoy = True
        self.annoy_status_var.set("Stopping... (will finish current operation)")
        self.stop_sequential_btn.configure(state=tk.DISABLED)
    
    def reset_annoy_ui(self):
        """Reset the annoy tab UI after stopping/completing"""
        self.run_sequential_btn.configure(state=tk.NORMAL if self.selected_devices else tk.DISABLED)
        self.stop_sequential_btn.configure(state=tk.DISABLED)
    
    def unblock_all_devices(self):
        """Unblock all devices in the blocklist"""
        if not self.connection:
            return
            
        try:
            self.status_var.set("Unblocking all devices...")
            self.root.update_idletasks()
            
            # Use an empty list to clear the blacklist
            response = self.wlan.filter_mac_addresses(
                mac_list=[],
                hostname_list=[],
                filter_status='2'  # '2' for blacklist
            )
            
            # Update UI
            self.refresh_all()
            self.status_var.set("All devices unblocked")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock devices: {str(e)}")
            self.status_var.set("Unblock operation failed")
    
    def refresh_annoying_devices(self):
        """Refresh the list of devices in the Annoy Them tab"""
        if not self.connection:
            return
            
        try:
            # Clear existing device boxes
            for widget in self.device_boxes_frame.winfo_children():
                widget.destroy()
            self.annoy_boxes = {}
            
            # Get connected devices
            host_list = self.wlan.host_list()
            
            # Clear monitoring tables
            for item in self.monitor_connected_tree.get_children():
                self.monitor_connected_tree.delete(item)
                
            for item in self.monitor_blocked_tree.get_children():
                self.monitor_blocked_tree.delete(item)
            
            # Get filtered devices for blocked monitoring
            filtered_devices = self.wlan.get_filtered_devices()
            blocked_macs = set()
            blocked_hostnames = {}
            
            for filter_info in filtered_devices:
                if filter_info['filter_type'] == 'blacklist':
                    for device in filter_info['devices']:
                        mac = device['mac'].upper()
                        hostname = device['hostname']
                        blocked_macs.add(mac)
                        blocked_hostnames[mac] = hostname
                        # Add to blocked monitoring table
                        self.monitor_blocked_tree.insert('', tk.END, values=(hostname,))
            
            # Fill device boxes and connected monitoring table with devices
            if 'Hosts' in host_list and 'Host' in host_list['Hosts']:
                hosts = host_list['Hosts']['Host']
                if not isinstance(hosts, list):
                    hosts = [hosts]
                
                for i, host in enumerate(hosts):
                    mac = host.get('MacAddress', '').upper()
                    hostname = host.get('HostName', 'Unknown')
                    
                    # Add to connected monitoring table
                    self.monitor_connected_tree.insert('', tk.END, values=(hostname,))
                    
                    # Create device box
                    box_frame = ttk.Frame(self.device_boxes_frame, style="DeviceBox.TFrame", padding=5, width=100, height=80)
                    box_frame.pack(side=tk.LEFT, padx=5, pady=5)
                    box_frame.pack_propagate(False)  # Fixed size
                    
                    # Set style based on selection status
                    if mac in self.selected_devices:
                        box_frame.configure(style="DeviceBoxSelected.TFrame")
                    
                    # Device name
                    ttk.Label(box_frame, text=hostname, wraplength=90, anchor=tk.CENTER).pack(pady=(5,0))
                    
                    # Configure click handler
                    box_frame.bind("<Button-1>", lambda event, m=mac, h=hostname, b=box_frame: 
                                 self.toggle_device_selection(m, h, b))
                    
                    # Store reference to the box and device info
                    self.annoy_boxes[hostname] = {
                        'frame': box_frame,
                        'mac': mac,
                        'hostname': hostname
                    }
            
            # Update canvas scroll region
            self.device_boxes_frame.update_idletasks()
            self.devices_canvas.configure(scrollregion=self.devices_canvas.bbox("all"))
            
            # Enable/disable buttons based on connection
            if self.connection:
                self.unblock_all_btn.configure(state=tk.NORMAL)
                if self.selected_devices:
                    self.run_sequential_btn.configure(state=tk.NORMAL)
            
        except Exception as e:
            self.status_var.set(f"Error refreshing annoy devices: {str(e)}")
    
    def refresh_all(self):
        """Refresh all device lists"""
        if not self.connection:
            return
        
        self.update_filter_status()
        self.refresh_connected_devices()
        self.refresh_filtered_devices()
        self.refresh_annoying_devices()
    
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
                self.unblock_all_btn.config(state=tk.NORMAL)
                
                # Start refresh thread
                self.refresh_thread = threading.Thread(target=self.auto_refresh, daemon=True)
                self.refresh_thread.start()
                
                self.status_var.set("Connected to " + url)
                self.refresh_all()
                
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
            
            # Clear devices and buttons
            self.clear_devices_ui()
            
            # Update UI
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.refresh_btn.config(state=tk.DISABLED)
            self.toggle_filter_btn.config(state=tk.DISABLED)
            self.unblock_all_btn.config(state=tk.DISABLED)
            self.run_sequential_btn.config(state=tk.DISABLED)
            self.stop_sequential_btn.config(state=tk.DISABLED)
            
            # Stop any running annoy process
            self.stop_annoy = True
            
            self.filter_status_label.config(text="Not connected", style="Badge.TLabel")
            self.status_var.set("Disconnected")
    
    def clear_devices_ui(self):
        """Clear all devices from UI and remove buttons"""
        # Clear connected devices
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Clear filtered devices
        for item in self.filtered_tree.get_children():
            self.filtered_tree.delete(item)
            
        # Remove all block buttons
        for button in self.connected_action_buttons.values():
            if button and button.winfo_exists():
                button.destroy()
        self.connected_action_buttons = {}
        
        # Remove all unblock buttons
        for button in self.filtered_action_buttons.values():
            if button and button.winfo_exists():
                button.destroy()
        self.filtered_action_buttons = {}
    
    def auto_refresh(self):
        while self.connection:
            time.sleep(30)  # Refresh every 30 seconds
            try:
                if self.connection:
                    self.root.after(0, self.refresh_all)
            except:
                pass
    
    def refresh_all(self):
        """Refresh both connected and filtered devices"""
        if not self.connection:
            return
        
        self.update_filter_status()
        self.refresh_connected_devices()
        self.refresh_filtered_devices()
        self.refresh_annoying_devices()
    
    def refresh_connected_devices(self):
        """Refresh the list of connected devices"""
        if not self.connection:
            return
            
        try:
            self.status_var.set("Refreshing connected devices...")
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
            
            # Clear current tree and buttons
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Clear old button references
            for button in self.connected_action_buttons.values():
                if button and button.winfo_exists():
                    button.destroy()
            self.connected_action_buttons = {}
            
            # Fill tree with devices
            if 'Hosts' in host_list and 'Host' in host_list['Hosts']:
                hosts = host_list['Hosts']['Host']
                if not isinstance(hosts, list):
                    hosts = [hosts]
                
                for host in hosts:
                    mac = host.get('MacAddress', '').upper()
                    hostname = host.get('HostName', 'Unknown')
                    ip = host.get('IpAddress', '')
                    
                    status = "Active"  # All devices here are active/connected
                    
                    # Insert item without the action column
                    item_id = self.tree.insert('', tk.END, values=(hostname, mac, ip, status))
                    
                    # Create block button for this device
                    block_button = ttk.Button(
                        self.block_buttons_frame,
                        text="Block",
                        width=10,
                        style="Block.TButton",
                        command=lambda m=mac, h=hostname: self.block_device(m, h)
                    )
                    block_button.pack(pady=2)
                    self.connected_action_buttons[item_id] = block_button
            
            connected_count = len(self.tree.get_children())
            self.status_var.set(f"Found {connected_count} connected devices")
            
        except Exception as e:
            self.status_var.set(f"Error refreshing connected devices: {str(e)}")
    
    def refresh_filtered_devices(self):
        """Refresh the list of filtered/blocked devices"""
        if not self.connection:
            return
            
        try:
            self.status_var.set("Refreshing filtered devices...")
            self.root.update_idletasks()
            
            # Get filtered devices
            filtered_devices = self.wlan.get_filtered_devices()
            
            # Clear current filtered tree and buttons
            for item in self.filtered_tree.get_children():
                self.filtered_tree.delete(item)
            
            # Clear old button references
            for button in self.filtered_action_buttons.values():
                if button and button.winfo_exists():
                    button.destroy()
            self.filtered_action_buttons = {}
            
            # Add all filtered devices to the filtered tree
            for filter_info in filtered_devices:
                filter_type = filter_info['filter_type']
                for device in filter_info['devices']:
                    mac = device['mac'].upper()
                    hostname = device['hostname']
                    
                    # Insert item
                    item_id = self.filtered_tree.insert('', tk.END, values=(hostname, mac, filter_type))
                    
                    # Create unblock button for this device
                    unblock_button = ttk.Button(
                        self.unblock_buttons_frame,
                        text="Unblock",
                        width=10,
                        style="Unblock.TButton",
                        command=lambda m=mac, h=hostname: self.unblock_device(m, h)
                    )
                    unblock_button.pack(pady=2)
                    self.filtered_action_buttons[item_id] = unblock_button
            
            filtered_count = len(self.filtered_tree.get_children())
            self.status_var.set(f"Found {filtered_count} filtered devices")
            
        except Exception as e:
            self.status_var.set(f"Error refreshing filtered devices: {str(e)}")
    
    def block_device(self, mac, hostname):
        """Block a device by MAC address"""
        try:
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
            self.refresh_all()
            self.status_var.set(f"Blocked {hostname}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block device: {str(e)}")
            self.status_var.set("Block operation failed")
    
    def unblock_device(self, mac, hostname):
        """Unblock a device by MAC address"""
        try:
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
            self.refresh_all()
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
            self.refresh_all()
            self.status_var.set(f"MAC filter {'enabled' if enabled else 'disabled'}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update filter: {str(e)}")
            self.status_var.set("Filter update failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetcutGUI(root)
    root.mainloop()