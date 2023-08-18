__all__ = ['Page', 'Scan_Page', 'Welcome_Page', 'MainView']

# NOTE:  Add an exception for checking VALID IP INPUT  (before actually running the IP)
# NOTE:  Disable the ability to press scan while a scan is already ongoing
# NOTE:  Add a refresh icon/animation while scan is ongoing?
# NOTE:  Add details frame below the table & show info for when a port is selected (instead of the test popup window)

# Import Libs
import os
import json
import tkinter as tk
from tkinter import ttk
from tkinter import font
from tkinter.messagebox import showinfo
from PIL import ImageTk, Image

import socket
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from src import resource_dir


# Default Page (structure that each Page inherits)
class Page(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)

        """ ====================
             PAGE CONFIGURATION
            ==================== """
        # Set the default fonts
        self.small_font = font.Font(self, family="Cambria", size=12)
        self.medium_font = font.Font(self, family="Cambria", size=14)
        self.large_font = font.Font(self, family="Cambria", size=16)
        self.title_font = font.Font(self, family="Tw Cen MT Condensed", size=18, weight="bold")

    """ Method to lift a page to the topmost "layer" (to view a page) """
    def show(self):
        # Raise page to the top of the "stack" of pages
        self.lift()


# Page 1 (Scan Page)
class Scan_Page(Page):
    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

        """ ========================
             INITIALIZE VARIABLE(S)
            ======================== """
        self.data = []  # For storing scanned port data
        self.ports_info = json.load(open(os.path.join(resource_dir, "ports.json")))

        """ ====================
             PAGE CONFIGURATION
            ==================== """

        # Scan Frame
        self.scan_frame = tk.Frame(self)

        # Scan button
        self.scan_button = tk.Button(self.scan_frame, text="Scan", font=self.small_font)
        self.scan_button.grid(row=0, column=0, padx=5, pady=2, sticky="w")

        # IP Address label above text input
        self.ip_label = tk.Label(self.scan_frame, text="IP Address:", font=self.small_font)
        self.ip_label.grid(row=0, column=1, padx=0, pady=5, sticky="w")

        # IP Address text input
        self.ip_entry_text = tk.StringVar()
        self.ip_entry_text.set("localhost")
        self.ip_entry = tk.Entry(self.scan_frame, textvariable=self.ip_entry_text, font=self.small_font, width=15)
        self.ip_entry.grid(row=0, column=2, padx=0, pady=5, sticky="w")
        # 'This Machine?' Checkbox
        self.ip_default_checkbox_var = tk.IntVar()
        self.ip_default_checkbox = tk.Checkbutton(self.scan_frame, text="This Machine?", variable=self.ip_default_checkbox_var,
                                                  onvalue=1, offvalue=0, height=2, width=10,
                                                  command=self.toggle_default_ip)
        self.ip_default_checkbox.grid(row=0, column=3, padx=0, pady=5, sticky="w")

        # Port Range label
        self.port_range_label = tk.Label(self.scan_frame, text="Port Range:", font=self.small_font)
        self.port_range_label.grid(row=0, column=4, padx=0, pady=5, sticky="w")
        # Port Range text input
        self.port_range_entry_text = tk.StringVar()
        self.port_range_entry_text.set("1-1024")
        self.port_range_entry = tk.Entry(self.scan_frame, textvariable=self.port_range_entry_text, font=self.small_font, width=11)
        self.port_range_entry.grid(row=0, column=5, padx=0, pady=5, sticky="w")

        # Place the scan frame
        self.scan_frame.grid(row=0, column=0, columnspan=5, padx=5, pady=5, sticky="w")

        """
        

        Scan Setting  Section (Scan protocol, Scan Speed, etc.)
        
        
        """
        




        # Scan Settings
        self.scan_settings_frame = tk.LabelFrame(self, text="Scan Settings", font=self.medium_font)
        self.scan_settings_frame.grid(row=1, column=0, columnspan=5, padx=5, pady=5, sticky="w")
    
        # Scan Settings - Scan protocol
        self.scan_protocol_label = tk.Label(self.scan_settings_frame, text="Protocol:", font=self.small_font)
        self.scan_protocol_label.grid(row=1, column=0, padx=0, pady=5, sticky="w")
        self.scan_protocol_var = tk.StringVar()
        self.scan_protocol_var.set("TCP")
        self.scan_protocol_dropdown = tk.OptionMenu(self.scan_settings_frame, self.scan_protocol_var, "TCP", "UDP")
        self.scan_protocol_dropdown.config(font=self.small_font, width=3)
        self.scan_protocol_dropdown.grid(row=1, column=1, padx=0, pady=5, sticky="w")

        # Scan Settings - Scan Speed
        self.scan_speed_label = tk.Label(self.scan_settings_frame, text="Speed:", font=self.small_font)
        self.scan_speed_label.grid(row=1, column=2, padx=0, pady=2, sticky="w")
        self.scan_speed_var = tk.StringVar()
        self.scan_speed_var.set("Fast")
        self.scan_speed_dropdown = tk.OptionMenu(self.scan_settings_frame, self.scan_speed_var, "Fast", "Slow", "Custom",command = self.toggle_custom_speed)
        self.scan_speed_dropdown.config(font=self.small_font, width=6)
        self.scan_speed_dropdown.grid(row=1, column=3, padx=0, pady=2, sticky="w",)




        # Scan Settings - Scan Speed - Custom
        self.scan_speed_custom_label = tk.Label(self.scan_settings_frame, text="", font=self.small_font)
        self.scan_speed_custom_label.grid(row=1, column=4, padx=0, pady=5, sticky="w")
        self.scan_speed_custom_entry_text = tk.StringVar()
        self.scan_speed_custom_entry_text.set("1000")
        self.scan_speed_custom_entry = tk.Entry(self.scan_settings_frame, textvariable=self.scan_speed_custom_entry_text,font=self.small_font, width="5")                       
        self.scan_speed_custom_entry.grid(row=1, column=5, padx=0, pady=5, sticky="w")
        self.scan_speed_custom_entry.config(state="disabled")
        

        # Scan Settings - Scan Speed - Custom - Unit
        self.scan_speed_custom_unit_label = tk.Label(self.scan_settings_frame, text="ms", font=self.small_font)
        self.scan_speed_custom_unit_label.grid(row=1, column=6, padx=0, pady=5, sticky="w")

        # Scan Setting - Scan Limit - Label
        self.scan_limit_label = tk.Label(self.scan_settings_frame, text="Limit:", font=self.small_font)
        self.scan_limit_label.grid(row=1, column=7, padx=0, pady=5, sticky="w")

        # Scan Setting - Scan Limit - Entry
        self.scan_limit_entry_text = tk.StringVar()
        self.scan_limit_entry_text.set("1000")
        self.scan_limit_entry = tk.Entry(self.scan_settings_frame, textvariable=self.scan_limit_entry_text, font=self.small_font, width="5")
        self.scan_limit_entry.grid(row=1, column=8, padx=5, pady=5, sticky="w")

        # Scan Setting - Show Open Ports Only - Checkbox
        self.show_ports_checkbox_var = tk.IntVar()
        self.show_ports_checkbox = tk.Checkbutton(self.scan_settings_frame, text="Show Open Ports", variable=self.show_ports_checkbox_var,
                                                  onvalue=1, offvalue=0, font=self.small_font, command=self.toggle_show_ports
                                                 )
        self.show_ports_checkbox.grid(row=1, column=9, padx=5, pady=5, sticky="w")


        
        




        """
        

        Results Table (for displaying scan results)
        

        """
        # Result table
        result_columns = ('ip', 'port_num', 'port_status', 'port_name', 'description')
        self.scan_results = ttk.Treeview(self, columns=result_columns, show='headings')

        # Set column heading data (id, text, width)
        columns = (('ip', 'IP Address', 100),
                   ('port_num', 'Port', 50),
                   ('port_status', 'Status', 80),
                   ('port_name', 'Port Name', 120),
                   ('description', 'Description', 340))

        # Set table heading names, column sizing, & data filtering command
        for col in columns:
            self.scan_results.heading(col[0], text=col[1], command=lambda _col=col[0]: self.filter_data(_col, True))
            self.scan_results.column(col[0], minwidth=0, width=col[2])

        # Set the action binding for when a table entry is clicked/selected
        self.scan_results.bind("<<TreeviewSelect>>", self.item_selected)

        # Place/position the results table
        self.scan_results.grid(row=2, column=0, padx=(5, 0), pady=5, columnspan=60, sticky="nsew")

        # Add a scrollbar to the results table
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.scan_results.yview)
        self.scan_results.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=2, column=60, sticky="ns")

        
        """ 
        #
        #
        #     Details Frame (for displaying details about a selected port)
        #
        #
        """
        
        
        # Details frame
        self.details = tk.Frame(self, background="white", highlightbackground="gray", highlightthickness=1)

        # Title
        self.details_title = tk.Label(self.details, text="Details", font=self.medium_font, background="white",)
        self.details_title.grid(row=0, column=0, padx=5, pady=1, sticky="n", )
        # Port Title ("Service: ")
        self.details_port_title = tk.Label(self.details, text="Service:", font=self.small_font, background="white")
        self.details_port_title.grid(row=1, column=0, padx=5, pady=1, sticky="w")
        # Port
        self.details_port = tk.Label(self.details, text="", font=self.small_font, background="white")
        self.details_port.grid(row=1, column=1, padx=(0, 5), pady=1, sticky="w")
        # Port Name Title ("Description: ")
        self.details_desc_title = tk.Label(self.details, text="Description:", font=self.small_font, background="white")
        self.details_desc_title.grid(row=2, column=0, padx=5, pady=1, sticky="w")
        # Port Name
        self.details_desc = tk.Label(self.details, text="", font=self.small_font, background="white")
        self.details_desc.grid(row=2, column=1, padx=(0, 5), pady=1, sticky="w")
        # Port Description Title ("Details: ")
        self.details_extended_title = tk.Label(self.details, text="Details:", font=self.small_font,
                                               height=2, anchor="n", background="white")
        self.details_extended_title.grid(row=3, column=0, padx=5, pady=1, sticky="w")
        # Port Description
        self.details_extended = tk.Label(self.details, text="", font=self.small_font,
                                         height=2, anchor="n", background="white", wraplength=580, justify="left")
        self.details_extended.grid(row=3, column=1, padx=(0, 5), pady=1, sticky="w")

        # Port Status Label
        self.details_status = tk.Label(self.details, text="", font=self.small_font, background="white", foreground="green")
        self.details_status.place(relx=0.95, y=20, anchor='ne')

        # Place Details FRAME
        self.details.grid(row=3, column=0, columnspan=60, padx=(5, 0), pady=(15, 5), sticky="nsew")

        # REMOVE FOCUS FROM WIDGET BY CLICKING OFF
        self.bind_all("<1>", lambda event: event.widget.focus_set())
    
        # Status label (for displaying scan status messages and errors)
        self.status_label = tk.Label(self, text="", font=self.small_font, fg="red")
        self.status_label.grid(row=5, column=0, columnspan=5, padx=5, pady=0, sticky="w")



  
    
    # Method for filtering result table data (runs when column header is clicked)
    def filter_data(self, column, reverse):
        l = [(self.scan_results.set(k, column), k) for k in self.scan_results.get_children('')]

        try:  # Numeric value
            l.sort(reverse=reverse, key=lambda tup: float(tup[0]))
        except ValueError:  # String value
            l.sort(reverse=reverse)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            self.scan_results.move(k, '', index)

        # Reverse the sort for the next run
        self.scan_results.heading(column, command=lambda _col=column: self.filter_data(_col, not reverse))

    # Method for deleting port 'data' variable
    def delete_data(self):
        self.data = []

    # Method for adding a port entry to the 'data' variable
    def add_data(self, ip, port, is_open, name, description):
        self.data.append((ip, port, is_open, name, description))

    # Method to clear the results table
    def clear_table(self):
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)

    # Method to update the table with the stored data ('data' var)
    def update_table(self):
        # Clear all current table data
        self.clear_table()

        # Check For Show Open Ports Only
        if self.show_ports_checkbox_var.get() == 1:
            # Add only open ports to table
            for item in self.data:
                if item[2]:
                    temp = [item[0],
                            item[1],
                            # Set status to 'Open'/'Closed' if is_open == True/False
                            'Open' if item[2] else 'Closed',
                            item[3],
                            item[4]]
                    self.scan_results.insert('', tk.END, values=temp)
        else:
            # Add all new data
            for item in self.data:
                temp = [item[0],
                        item[1],
                        # Set status to 'Open'/'Closed' if is_open == True/False
                        'Open' if item[2] else 'Closed',
                        item[3],
                        item[4]]
                self.scan_results.insert('', tk.END, values=temp)
    
    def toggle_default_ip(self):
        if self.ip_default_checkbox_var.get() == 1:
            self.ip_entry.config(state='disabled')
            self.ip_entry_text.set("localhost")
        elif self.ip_default_checkbox_var.get() == 0:
            self.ip_entry.config(state='normal')
    
    # Toggle custom speed based on scan_speed_dropdown
    def toggle_custom_speed(self, event):

        # Update custom speed entry based on scan speed dropdown selection (Fast, Slow)
        if self.scan_speed_var.get() == "Fast":
            self.scan_speed_custom_entry_text.set(1000)
        elif self.scan_speed_var.get() == "Slow":
            self.scan_speed_custom_entry_text.set(3000)

        # If custom speed is selected, enable custom speed entry
        if self.scan_speed_var.get() == "Custom":
            self.scan_speed_custom_entry.config(state='normal')
        else:
            self.scan_speed_custom_entry.config(state='disabled')

    # Toggle Show only open ports checkbox
    def toggle_show_ports(self):
        # Check if table is empty
        if len(self.scan_results.get_children()) == 0:
            return
        else:
            # Update table
            self.update_table()
            

    def item_selected(self, event):
        # record[n]
        # 0=IP ; 1=port ; 2=Status ; 3=PortName ; 4=PortDescription
        for selected_item in self.scan_results.selection():
            item = self.scan_results.item(selected_item)
            record = item['values']
            print(record[0])
            print(record[1])
            print(record[2])
            print(record[3])
            print(record[4])

            # Update details
            self.details_port.config(text=record[1])
            self.details_desc.config(text=record[3] if record[3] != "N/A" else "")
            self.details_extended.config(text=record[4] if record[4] != "N/A" else "")
            self.details_status.config(text=record[2].upper(), foreground="red" if record[2] == "Open" else "green")

            # show a message
            # showinfo(title='Information', message=''.join(str(record)))


# Page 2  -  Welcome
class Welcome_Page(Page):
    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

        """ ========================
             INITIALIZE VARIABLE(S)
            ======================== """
        # ...

        """ ====================
             PAGE CONFIGURATION
            ==================== """
        # Back button
        self.back_button = tk.Button(self, text="Back", font=self.small_font)

        # LabelFrame
        self.frame = tk.LabelFrame(self, text="Thank you for using PortScanner!", font=self.title_font)

        self.label1 = tk.Label(self.frame, text="What is PortScanner?", font=self.medium_font)

        # Place / position everything
        self.back_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.frame.grid(row=1, column=0, padx=5, pady=20, sticky="ew")

        # Label
        self.label1.grid(row=0, column=0, padx=5, pady=(20, 10), sticky="n")


# Page 3  -  About
class About_Page(Page):
    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

        """ ========================
             INITIALIZE VARIABLE(S)
            ======================== """
        # Initialize logo image
        # Create an object of tkinter ImageTk
        # Using this to include the picture of Grab the Axe in the about screen.
        logo_im = Image.open(os.path.join(resource_dir, "logo.png"))
        logo_resize = logo_im.resize((150, 150))
        self.logo_img = ImageTk.PhotoImage(logo_resize)

        # Description text
        description1 = "GRAB THE AXE provides both physical and cybersecurity consultations and assessments to help " \
                       "you lock your digital doors. Our goal is to reduce your losses and harden your lines of " \
                       "defense in both the real world and virtual, allowing you to focus on what you do best! By " \
                       "leveraging the most modern and innovative approaches and utilizing client feedback, we can " \
                       "pinpoint the focus areas that will offer you the greatest ROI."
        description2 = "Our team is highly experienced with Physical and Cyber Security, Threat Intelligence, " \
                       "Emergency Response, Vulnerability Management, Data Protection, Cloud and IoT Security. " \
                       "We help you reduce RISK, LIABILITY, and the inevitable LOSS OF TRUST from your customers in " \
                       "the face of any breach. Our experts are ready to help you protect what you care about!"

        """ ====================
             PAGE CONFIGURATION
            ==================== """
        # Back button
        self.back_button = tk.Button(self, text="Back", font=self.small_font)

        # LabelFrame
        self.frame = tk.LabelFrame(self, text="Thank you for using PortScanner!", font=self.title_font)

        # Left/Right Column FRAMES
        self.frame_left = tk.Frame(self.frame)
        self.frame_right = tk.Frame(self.frame)

        # Content labels (LEFT)
        self.label1 = tk.Label(self.frame_left, text="About Us", font=self.medium_font)
        self.label2 = tk.Label(self.frame_left, text="We are...", font=self.small_font)

        # Label widget to display the logo image (LEFT)
        self.logo_label = tk.Label(self.frame_left, image=self.logo_img)

        # Labels for description text (RIGHT)
        self.label_description1 = tk.Label(self.frame_right, text=description1, font=self.small_font, wraplength=520)
        self.label_description2 = tk.Label(self.frame_right, text=description2, font=self.small_font, wraplength=520)

        # Place / position everything
        self.back_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.frame.grid(row=1, column=0, padx=5, pady=20, sticky="ew")

        # Labels (LEFT)
        self.label1.grid(row=0, column=0, padx=2, pady=4, sticky="n")
        self.label2.grid(row=1, column=0, padx=2, pady=4, sticky="n")
        # Logo (LEFT)
        self.logo_label.grid(row=2, column=0, padx=5, pady=5, sticky="n")
        # Descriptions (RIGHT)
        self.label_description1.grid(row=0, column=0, padx=5, pady=5, sticky="n")
        self.label_description2.grid(row=1, column=0, padx=5, pady=5, sticky="n")

        # LEFT/RIGHT COLUMN FRAMES
        self.frame_left.grid(row=0, column=0, sticky="w")
        self.frame_right.grid(row=0, column=1, sticky="e")


# Main Controller class - primary window container - contains, controls & views Page(s)
class MainView(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)

        self.queue = None  # Initialize queue

        """ ========================
             INITIALIZE VARIABLE(S)
            ======================== """
        self.machine_ip = socket.gethostbyname(socket.gethostname())

        # Initialize host target
        self.target = self.machine_ip

        # Initialize scan protocol
        self.scan_protocol = "TCP"

        # Initialize port range
        self.port_range = "1-1024"

        # Initialize Scan speed
        self.scan_speed = "Fast"

        # Initialize Scan Limit
        self.scan_limit = 100



        # INITIALIZE the Menubar
        # NOTE: This is ADDED TO THE CONTAINER in 'app.py'
        self.menubar = self.initialize_menubar()

        """ ======================
             WINDOW CONFIGURATION
            ====================== """
        # Create object for each Page
        self.scan_obj = Scan_Page(self)
        self.welcome_obj = Welcome_Page(self)
        self.about_obj = About_Page(self)

        # Create container to hold all content  -  CONTAINS Page(s)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        # Place all pages (stacked atop one another) in the 'container' Frame
        self.scan_obj.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.welcome_obj.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.about_obj.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

        # BUTTON CONFIGURATION
        self.scan_obj.scan_button.config(command=self.start_scan)
        self.welcome_obj.back_button.config(command=self.goto_main_page)
        self.about_obj.back_button.config(command=self.goto_main_page)

        # Display the 1st page!
        self.scan_obj.show()

    # Method to initialize the menubar  -  returns instance of Menubar
    def initialize_menubar(self):
        menubar = tk.Menu(self)

        # FILE
        file_menu = tk.Menu(menubar, tearoff=0)

        file_menu.add_command(label='Scan', command=self.start_scan)
        file_menu.add_separator()
        file_menu.add_command(label='Save')
        file_menu.add_command(label='Save As...')
        file_menu.add_separator()
        file_menu.add_command(label='Exit', command=self.master.destroy)

        # VIEW
        view_menu = tk.Menu(menubar, tearoff=0)

        # SETTINGS
        settings_menu = tk.Menu(menubar, tearoff=0)

        #
        # Settings  ->  Preferences
        preferences_menu = tk.Menu(settings_menu, tearoff=0)
        preferences_menu.add_command(label='Keyboard Shortcuts')

        # Settings  ->  Preferences  ->  Font Preferences
        font_preferences = tk.Menu(preferences_menu, tearoff=0)
        font_preferences.add_command(label='Font Size')
        font_preferences.add_command(label='Font Style')

        # ADD SUB-MENU CASCADES TO MENU OPTIONS
        preferences_menu.add_cascade(label='Font Preferences', menu=font_preferences)
        settings_menu.add_cascade(label='Preferences', menu=preferences_menu)

        # HELP
        help_menu = tk.Menu(menubar, tearoff=0)

        help_menu.add_command(label='Welcome', command=self.goto_welcome_page)
        help_menu.add_command(label='About', command=self.goto_about_page)

        # ADD ALL DROPDOWN BUTTONS TO THE MENUBAR
        menubar.add_cascade(label='File', menu=file_menu)
        menubar.add_cascade(label='View', menu=view_menu)
        menubar.add_cascade(label='Settings', menu=settings_menu)
        menubar.add_cascade(label='Help', menu=help_menu)

        return menubar

    # Method for lifting Page1 to the top of the stack
    def goto_main_page(self):
        self.scan_obj.show()

    # Method for lifting Page2 to the top of the stack
    def goto_welcome_page(self):
        self.welcome_obj.show()

    def goto_about_page(self):
        self.about_obj.show()
    
    # Validate port range input
    def validate_port_range(self, input_port):
        print("testing")
        # Print debug "test"
        print("Validating port range: " + input_port)
        # Check if input is a valid port or range of ports
        if input_port.replace("-", "").isnumeric() and (input_port.count("-") == 1 or input_port.isnumeric()):
            range_ports = input_port.split("-")
            # Check if range_ports has empty values
            if "" in range_ports:
                self.scan_obj.status_label.config(text="Invalid port range. Please enter a valid range between 0 - 65535.", fg="red")
                return False
            if int(range_ports[0]) < 0 or int(range_ports[-1]) > 65535:
                self.scan_obj.status_label.config(text="Invalid port range. Please enter a valid range between 0 - 65535.", fg="red")
                return False
            return True
        else:
            self.scan_obj.status_label.config(text="Invalid port range. Please enter a valid range between 0 - 65535.", fg="red")
            return False

    # Method for starting the Port Scanning process
    def start_scan(self):
        # Update the target host with IP address FROM THE TEXTBOX
        self.target = self.scan_obj.ip_entry_text.get()

        # Update the range of ports to scan with PORT RANGE FROM THE TEXTBOX
        self.port_range = self.scan_obj.port_range_entry_text.get()

        # Update Scan protocol
        self.scan_protocol = self.scan_obj.scan_protocol_var.get()

        # Update Scan Speed
        self.scan_speed = self.scan_obj.scan_speed_var.get()

        # Update Custom Speed Value 
        self.custom_speed = self.scan_obj.scan_speed_custom_entry_text.get()

        # Update Scan Limit
        self.scan_limit = self.scan_obj.scan_limit_entry_text.get()

        # Convert Scan text to value
        if self.scan_speed == "Slow":
            self.scan_speed = 3000
        elif self.scan_speed == "Fast":
            self.scan_speed = 1000
        elif self.scan_speed == "Custom":
            self.scan_speed = int(self.custom_speed)


        # Convert Scan Speed to seconds from ms
        self.scan_speed = int(self.scan_speed) / 1000

        # Run validation on the port range
        if(self.validate_port_range(self.port_range) == False):
            return False
        
        # Clear the error label
        self.scan_obj.status_label.config(text="")

        # Check if single port or range of ports
        if "-" in self.port_range:
            # Split the string into a list of 2 strings
            self.port_range = self.port_range.split("-")
            # Convert the strings to integers
            self.port_range_start = int(self.port_range[0])
            self.port_range_end = int(self.port_range[1])
        else:
            # Convert the string to an integer
            self.port_range_start = int(self.port_range)
            self.port_range_end = int(self.port_range)
        
        # Initialize list of ports to scan using 'port list' input       
        self.port_list = range(self.port_range_start, self.port_range_end + 1)

        # DISABLE SCAN BUTTON
        self.scan_obj.scan_button["state"] = "disabled"

        # Change the text of the scan button to "Scanning"
        self.scan_obj.scan_button.config(text="Scanning")

        # Delete all data (to be replaced by updated scan data results)
        self.scan_obj.delete_data()
        # Clear the table (so it shows empty WHILE it scans!!!)
        self.scan_obj.update_table()

        # Set Status Label to "Scanning..." with scan_protocol and port_range
        self.scan_obj.status_label.config(text="Scanning " + self.scan_protocol + " ports " + self.port_range[0] + "-" + self.port_range[1] + "...", fg="green")
        # Initialize queue
        self.queue = queue.Queue()



        # Start the PortScanner thread  (send the parameters: target ip & range of ports, scan protocol)
        ThreadedPortScanner(self.queue, args=(self.target, self.port_list, self.scan_protocol, self.scan_limit, self.scan_speed)).start()

        # Check the progress (run self.process_queue() method) after 100ms passes
        self.master.after(100, self.process_queue)


    # Method for checking the progress of the PortScanning thread (for checking completion)
    def process_queue(self):
        try:  # If the thread process has completed (when 'data' has been added to the queue)
            msg = self.queue.get_nowait()  # Retrieving data from PortScanner thread queue
            self.scan_obj.data = msg  # Updating the 'data' variable
            self.scan_obj.update_table()  # Updating the result table
            
            # Reset the text of the scan button to "Scan"
            self.scan_obj.scan_button.config(text="Scan")
            # RE-ENABLE SCAN BUTTON
            self.scan_obj.scan_button["state"] = "normal"
            # Set Status Label to "Scan Complete" (to show that the scan has completed)
            self.scan_obj.status_label.config(text="Scan Complete", fg="green")

        except queue.Empty:  # Otherwise...
            # Re-check (run the method again) after another 100ms
            self.master.after(100, self.process_queue)


# PortScanner thread (runs separately from the main tkinter GUI thread)
class ThreadedPortScanner(threading.Thread):
    def __init__(self, q, args=(), kwargs=None):
        threading.Thread.__init__(self, args=(), kwargs=None)

        self.queue = q  # Set the queue

        # Retrieve the given parameters (convert the Iterable to a list)
        params = []
        for x in args:
            params.append(x)

        self.target = params[0]  # Set the 1st parameter (target ip) as a variable
        self.port_list = params[1]  # Set the 2nd parameter (port range) as a variable
        self.scan_protocol = params[2] # Set the 3rd parameter (scan protocol) as a variable
        self.scan_limit = params[3] # Set the 4th parameter (scan limit) as a variable
        self.scan_speed = params[4] # Set the 5th parameter (scan speed) as a variable

        # Initialize the 'data' list
        self.data = []

    # What happens during the thread process
    def run(self):
        print("\nSCANNING...")

        # Start the port scan
        self.scan()

        # (after the port scan is done)
        # Send the 'data' to the queue (which is caught in the Tkinter GUI thread, and retrieved there)
        self.queue.put(self.data)



    # Method to check if a port is open
    def is_port_open(self, target, port):
        # Define socket with exceptions
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            
            # Set socket timeout based on the scan speed
            sock.settimeout(self.scan_speed)
            
            

            # Check which protocol is being used
            if self.scan_protocol == "TCP":
                # Try to connect to the port
                try:
                    sock.connect((target, port))
                    return True
                except:
                    return False
                    


    def scan(self):
        # Create Thread Pool (as 'executor')
        with ThreadPoolExecutor(min(len(self.port_list), int(self.scan_limit))) as executor:
            # Call map() to run and execute the is_port_open() method over all ports in the 'port_list'
            result = executor.map(self.is_port_open, [self.target]*len(self.port_list), self.port_list)

            # Iterate the results + port numbers
            for port, is_open in zip(self.port_list, result):
                # ADD PORT ENTRY to 'data' variable
                self.data.append((
                    self.target, port, is_open, self.get_port_name(port), self.get_port_description(port)
                ))

                # If the port is open, output to console
                if is_open:
                    print(f'Port {port} is open!')

    def get_port_name(self, port):
        f = open(os.path.join(resource_dir, "ports.json"))
        ports_info = json.load(f)

        #Create a check to catch keyerror if higher than avalible

        try:
            port_name = ports_info["data"][str(port)][0]
        except KeyError:
            port_name = "N/A"

       

        if port_name == "NA":
            port_name = "N/A"

        f.close()

        return port_name
        # return f'Port {port} NAME'  # placeholder

    def get_port_description(self, port):
        f = open(os.path.join(resource_dir, "ports.json"))
        ports_info = json.load(f)

        try:
            port_description = ports_info["data"][str(port)][1]
        except KeyError:
            port_description = "N/A"

        if port_description == "NA":
            port_description = "N/A"

        f.close()

        return port_description
        # return f'Port {port} DESCRIPTION'  # placeholder
