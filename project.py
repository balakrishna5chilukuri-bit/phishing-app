import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
from datetime import datetime
from urllib.parse import urlparse
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.patches as patches
import numpy as np

class PhishingDetectionDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Detection System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # --- MORE DATA ADDED ---
        # Mock data expanded for a full year and more categories
        self.phishing_data = {
            "trends": [
                {"month": "Jan", "phishingEmails": 145, "spoofingAttempts": 89, "maliciousUrls": 112},
                {"month": "Feb", "phishingEmails": 159, "spoofingAttempts": 97, "maliciousUrls": 128},
                {"month": "Mar", "phishingEmails": 170, "spoofingAttempts": 105, "maliciousUrls": 143},
                {"month": "Apr", "phishingEmails": 201, "spoofingAttempts": 118, "maliciousUrls": 167},
                {"month": "May", "phishingEmails": 238, "spoofingAttempts": 127, "maliciousUrls": 195},
                {"month": "Jun", "phishingEmails": 250, "spoofingAttempts": 140, "maliciousUrls": 210},
                {"month": "Jul", "phishingEmails": 265, "spoofingAttempts": 155, "maliciousUrls": 225},
                {"month": "Aug", "phishingEmails": 240, "spoofingAttempts": 130, "maliciousUrls": 200},
                {"month": "Sep", "phishingEmails": 280, "spoofingAttempts": 160, "maliciousUrls": 240},
                {"month": "Oct", "phishingEmails": 310, "spoofingAttempts": 180, "maliciousUrls": 270},
                {"month": "Nov", "phishingEmails": 350, "spoofingAttempts": 210, "maliciousUrls": 300},
                {"month": "Dec", "phishingEmails": 330, "spoofingAttempts": 190, "maliciousUrls": 280}
            ],
            "distribution": [
                {"name": "Financial", "value": 30},
                {"name": "Cloud Services", "value": 20},
                {"name": "Email Service", "value": 15},
                {"name": "E-commerce", "value": 12},
                {"name": "Government", "value": 10},
                {"name": "Healthcare", "value": 8},
                {"name": "Social Media", "value": 5}
            ],
            "stats": {
                "totalAttacks": "28,741",
                "successRate": "19%",
                "mostTargeted": "Financial",
                "commonVector": "Email Links"
            }
        }
        
        # Expanded sample results for a more populated history
        self.sample_results = [
            {
                "id": 1,
                "url": "https://paypal-secure.verifynow-id.com/login",
                "risk": "High",
                "score": 87,
                "timestamp": "2025-09-25 10:23:15",
                "findings": [
                    {"description": "Brand impersonation detected", "details": "PayPal impersonation"},
                    {"description": "Domain was registered recently", "details": "Domain age: 3 days old (Simulated)"},
                    {"description": "Suspicious URL pattern", "details": "Multiple subdomains used to obfuscate"}
                ]
            },
            {
                "id": 2,
                "url": "http://chase-online-security.info/update/login.html",
                "risk": "High",
                "score": 92,
                "timestamp": "2025-09-25 09:45:10",
                "findings": [
                    {"description": "Brand impersonation detected", "details": "Possible Chase bank impersonation"},
                    {"description": "Suspicious top-level domain", "details": "The TLD .info is often used in phishing attacks"},
                    {"description": "No valid SSL certificate", "details": "The website does not use HTTPS, which is insecure"}
                ]
            },
            {
                "id": 3,
                "url": "http://182.16.24.78/coinbase/verify",
                "risk": "High",
                "score": 88,
                "timestamp": "2025-09-24 18:11:42",
                "findings": [
                    {"description": "IP address used instead of domain name", "details": "Using IP addresses in URLs is a common phishing tactic"},
                    {"description": "Brand impersonation detected", "details": "Possible Coinbase impersonation"}
                ]
            },
            {
                "id": 4,
                "url": "https://onedrive-live-share.ga/documents",
                "risk": "Medium",
                "score": 68,
                "timestamp": "2025-09-24 15:30:05",
                "findings": [
                    {"description": "Brand impersonation detected", "details": "Possible Microsoft OneDrive impersonation"},
                    {"description": "Suspicious top-level domain", "details": "The TLD .ga is often used in phishing attacks"}
                ]
            },
            {
                "id": 5,
                "url": "https://microsoft365-update.org/verify.php",
                "risk": "Medium",
                "score": 63,
                "timestamp": "2025-09-24 11:15:32",
                "findings": [
                    {"description": "Brand impersonation detected", "details": "Microsoft impersonation"},
                    {"description": "No valid SSL certificate", "details": "The website uses an invalid certificate"}
                ]
            },
            {
                "id": 6,
                "url": "http://netflx-support.com/billing",
                "risk": "Medium",
                "score": 55,
                "timestamp": "2025-09-23 20:05:19",
                "findings": [
                    {"description": "Brand impersonation detected", "details": "Possible Netflix impersonation (typo-squatting)"},
                    {"description": "No valid SSL certificate", "details": "The website does not use HTTPS"}
                ]
            },
            {
                "id": 7,
                "url": "https://bit.ly/3xY4zAb",
                "risk": "Medium",
                "score": 45,
                "timestamp": "2025-09-23 14:22:51",
                "findings": [
                    {"description": "URL shortener used", "details": "Shorteners like bit.ly can hide the true destination of the link"}
                ]
            },
            {
                "id": 8,
                "url": "https://amazon.com/account",
                "risk": "Low",
                "score": 12,
                "timestamp": "2025-09-23 08:45:03",
                "findings": []
            },
            {
                "id": 9,
                "url": "https://github.com/features/actions",
                "risk": "Low",
                "score": 5,
                "timestamp": "2025-09-22 16:50:21",
                "findings": []
            },
            {
                "id": 10,
                "url": "https://google.com",
                "risk": "Low",
                "score": 2,
                "timestamp": "2025-09-22 10:18:00",
                "findings": []
            }
        ]
        
        self.current_scan_result = None
        self.setup_ui()
    
    def setup_ui(self):
        # Create main header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(header_frame, text="Phishing Detection System", 
                               font=('Arial', 16, 'bold'), fg='white', bg='#2c3e50')
        header_label.pack(pady=15)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_history_tab()
    
    def create_dashboard_tab(self):
        # Dashboard tab
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Stats cards frame
        stats_frame = tk.Frame(dashboard_frame, bg='#f0f0f0')
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        # Create stats cards
        stats = [
            ("Total Attacks", self.phishing_data["stats"]["totalAttacks"]),
            ("Success Rate", self.phishing_data["stats"]["successRate"]),
            ("Most Targeted", self.phishing_data["stats"]["mostTargeted"]),
            ("Common Vector", self.phishing_data["stats"]["commonVector"])
        ]
        
        for i, (label, value) in enumerate(stats):
            card_frame = tk.Frame(stats_frame, bg='white', relief='raised', bd=1)
            card_frame.grid(row=0, column=i, padx=10, pady=5, sticky='ew')
            stats_frame.grid_columnconfigure(i, weight=1)
            
            tk.Label(card_frame, text=label, font=('Arial', 10), 
                    fg='#666', bg='white').pack(pady=(10, 0))
            tk.Label(card_frame, text=value, font=('Arial', 14, 'bold'), 
                    bg='white').pack(pady=(0, 10))
        
        # Charts frame
        charts_frame = tk.Frame(dashboard_frame, bg='#f0f0f0')
        charts_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create charts
        self.create_charts(charts_frame)
    
    def create_charts(self, parent):
        # Create matplotlib figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        fig.patch.set_facecolor('#f0f0f0')
        
        # Trends chart (Bar chart)
        months = [item["month"] for item in self.phishing_data["trends"]]
        phishing_emails = [item["phishingEmails"] for item in self.phishing_data["trends"]]
        spoofing_attempts = [item["spoofingAttempts"] for item in self.phishing_data["trends"]]
        malicious_urls = [item["maliciousUrls"] for item in self.phishing_data["trends"]]
        
        x = np.arange(len(months))
        width = 0.25
        
        ax1.bar(x - width, phishing_emails, width, label='Phishing Emails', color='#8884d8')
        ax1.bar(x, spoofing_attempts, width, label='Spoofing Attempts', color='#82ca9d')
        ax1.bar(x + width, malicious_urls, width, label='Malicious URLs', color='#ffc658')
        
        ax1.set_xlabel('Month')
        ax1.set_ylabel('Count')
        ax1.set_title('Phishing Attack Trends (12 Months)')
        ax1.set_xticks(x)
        ax1.set_xticklabels(months, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        fig.tight_layout(pad=3.0)
        
        # Distribution chart (Pie chart)
        labels = [item["name"] for item in self.phishing_data["distribution"]]
        values = [item["value"] for item in self.phishing_data["distribution"]]
        colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))

        ax2.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax2.set_title('Attack Target Distribution')
        ax2.axis('equal') # Equal aspect ratio ensures that pie is drawn as a circle.
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def create_scanner_tab(self):
        # Scanner tab
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="URL Scanner")
        
        # Scanner input frame
        input_frame = tk.Frame(scanner_frame, bg='white', relief='raised', bd=1)
        input_frame.pack(fill='x', padx=20, pady=20)
        
        tk.Label(input_frame, text="URL Scanner", font=('Arial', 14, 'bold'), 
                bg='white').pack(pady=(15, 10))
        
        # URL input
        url_frame = tk.Frame(input_frame, bg='white')
        url_frame.pack(fill='x', padx=20, pady=10)
        
        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(url_frame, textvariable=self.url_var, font=('Arial', 11))
        self.url_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        self.url_entry.bind('<Return>', lambda e: self.scan_url())
        
        self.scan_button = tk.Button(url_frame, text="Scan URL", command=self.scan_url,
                                    bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
        self.scan_button.pack(side='right')
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        self.progress_label = tk.Label(input_frame, textvariable=self.progress_var, 
                                      bg='white', fg='#666')
        self.progress_label.pack(pady=(0, 15))
        
        # Results frame
        self.results_frame = tk.Frame(scanner_frame, bg='#f0f0f0')
        self.results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
    
    def create_history_tab(self):
        # History tab
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="Scan History")
        
        # Title
        title_frame = tk.Frame(history_frame, bg='white', relief='raised', bd=1)
        title_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        tk.Label(title_frame, text="Scan History", font=('Arial', 14, 'bold'),
                bg='white').pack(pady=15)
        
        # History table
        table_frame = tk.Frame(history_frame, bg='white', relief='raised', bd=1)
        table_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Create treeview for table
        columns = ('URL', 'Risk Level', 'Score', 'Scan Time')
        self.history_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        for col in columns:
            self.history_tree.heading(col, text=col)
        self.history_tree.column('URL', width=400)
        self.history_tree.column('Risk Level', width=100, anchor='center')
        self.history_tree.column('Score', width=80, anchor='center')
        self.history_tree.column('Scan Time', width=150, anchor='center')

        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.history_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        # Populate history
        self.populate_history()
        
        # Bind double-click event
        self.history_tree.bind('<Double-1>', self.on_history_select)
        
        # View details button
        button_frame = tk.Frame(table_frame, bg='white')
        button_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        tk.Button(button_frame, text="View Selected Details", command=self.view_history_details,
                 bg='#3498db', fg='white', font=('Arial', 10, 'bold')).pack()
    
    def populate_history(self):
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add all results to history
        for result in self.sample_results:
            self.history_tree.insert('', 'end', values=(
                result['url'][:80] + '...' if len(result['url']) > 80 else result['url'],
                result['risk'],
                f"{result['score']}%",
                result['timestamp']
            ), tags=(result['id'],))
    
    def on_history_select(self, event):
        self.view_history_details()
    
    def view_history_details(self):
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan result to view details.")
            return
        
        # Get the selected item's ID
        item = self.history_tree.item(selection[0])
        result_id = int(self.history_tree.item(selection[0], 'tags')[0])
        
        # Find the corresponding result
        result = next((r for r in self.sample_results if r['id'] == result_id), None)
        if result:
            # Switch to scanner tab and display results
            self.notebook.select(1)  # Scanner tab is index 1
            self.url_var.set(result['url'])
            self.display_scan_results(result)
    
    def scan_url(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return
        
        # Disable scan button and show progress
        self.scan_button.config(state='disabled', text='Scanning...')
        self.progress_var.set("Scanning URL for phishing indicators...")
        
        # Run scan in separate thread to prevent UI freezing
        def scan_thread():
            time.sleep(1.5)  # Simulate network delay
            result = self.perform_url_scan(url)
            
            # Update UI in main thread
            self.root.after(0, lambda: self.scan_complete(result))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def perform_url_scan(self, url):
        """Perform URL scanning with heuristic analysis"""
        score = 0
        findings = []
        
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.hostname.lower() if parsed_url.hostname else ""
            
            # --- ENHANCED SCANNER ---
            # Check for '@' symbol in domain (URL credential inclusion)
            if '@' in domain:
                score += 25
                findings.append({
                    "description": "At symbol '@' found in domain",
                    "details": "This can be a technique to trick users about the actual domain name."
                })

            # Check for IP address in URL
            if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                score += 25
                findings.append({
                    "description": "IP address used instead of domain name",
                    "details": "Using IP addresses in URLs is a common phishing tactic"
                })
            
            # Check for brand names in domain
            brands = ["paypal", "apple", "microsoft", "google", "amazon", "facebook", "chase", "netflix", "coinbase"]
            
            for brand in brands:
                if brand in domain and not domain.endswith(f"{brand}.com"):
                    score += 30
                    findings.append({
                        "description": "Brand impersonation detected",
                        "details": f"Possible {brand} impersonation"
                    })
                    break
            
            # Check for excessive subdomains
            parts = domain.split('.')
            if len(parts) > 4: # Increased threshold slightly
                score += 15
                findings.append({
                    "description": "Excessive number of subdomains",
                    "details": "Multiple subdomains may be used to obscure the true domain"
                })
            
            # Check for suspicious TLDs
            suspicious_tlds = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'club', 'top']
            if parts and parts[-1] in suspicious_tlds:
                score += 15
                findings.append({
                    "description": "Suspicious top-level domain",
                    "details": f"The TLD .{parts[-1]} is often used in phishing attacks"
                })
            
        except Exception as e:
            score += 20
            findings.append({
                "description": "Invalid URL format",
                "details": "The URL appears to be malformed"
            })
        
        # Clamp score to 100
        score = min(score, 100)

        # Determine risk level
        if score >= 75:
            risk = "High"
        elif score >= 40:
            risk = "Medium"
        else:
            risk = "Low"
        
        return {
            "id": int(datetime.now().timestamp()),
            "url": url,
            "risk": risk,
            "score": score,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings
        }
    
    def scan_complete(self, result):
        # Re-enable scan button
        self.scan_button.config(state='normal', text='Scan URL')
        self.progress_var.set("Scan completed")
        
        # Store and display results
        self.current_scan_result = result
        
        # Add new result to history (insert at beginning for newest first)
        self.sample_results.insert(0, result)
        
        # Refresh history table
        self.populate_history()
        
        # Display scan results
        self.display_scan_results(result)
    
    def display_scan_results(self, result):
        # Clear previous results
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        if not result:
            return
        
        # Results container
        results_container = tk.Frame(self.results_frame, bg='white', relief='raised', bd=1)
        results_container.pack(fill='both', expand=True)
        
        # Header
        header_frame = tk.Frame(results_container, bg='white')
        header_frame.pack(fill='x', padx=20, pady=(15, 10))
        
        tk.Label(header_frame, text="Scan Results", font=('Arial', 14, 'bold'),
                bg='white').pack(side='left')
        
        # Risk indicator
        risk_color = {'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#27ae60'}
        risk_label = tk.Label(header_frame, text=f"{result['risk']} Risk ({result['score']}%)",
                             font=('Arial', 12, 'bold'), fg=risk_color.get(result['risk'], '#333'),
                             bg='white')
        risk_label.pack(side='right')
        
        # URL section
        url_frame = tk.Frame(results_container, bg='white')
        url_frame.pack(fill='x', padx=20, pady=5)
        
        tk.Label(url_frame, text="URL:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        tk.Label(url_frame, text=result['url'], font=('Arial', 10), bg='white', 
                wraplength=800, justify='left').pack(anchor='w')
        
        # Timestamp section
        time_frame = tk.Frame(results_container, bg='white')
        time_frame.pack(fill='x', padx=20, pady=5)
        
        tk.Label(time_frame, text="Scan Time:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        tk.Label(time_frame, text=result['timestamp'], font=('Arial', 10), bg='white').pack(anchor='w')
        
        # Findings section
        findings_frame = tk.Frame(results_container, bg='white')
        findings_frame.pack(fill='both', expand=True, padx=20, pady=5)
        
        tk.Label(findings_frame, text="Findings:", font=('Arial', 10, 'bold'), bg='white').pack(anchor='w')
        
        if result['findings']:
            # Create scrollable text widget for findings
            findings_text = scrolledtext.ScrolledText(findings_frame, height=8, width=80, 
                                                     wrap=tk.WORD, font=('Arial', 9))
            findings_text.pack(fill='both', expand=True, pady=(5, 10))
            
            for i, finding in enumerate(result['findings'], 1):
                findings_text.insert(tk.END, f"{i}. {finding['description']}\n")
                findings_text.insert(tk.END, f"   Details: {finding['details']}\n\n")
            
            findings_text.config(state='disabled')
        else:
            tk.Label(findings_frame, text="No suspicious indicators detected", 
                    font=('Arial', 10), fg='#27ae60', bg='white').pack(anchor='w', pady=5)
        
        # Recommendations for high/medium risk
        if result['risk'] != 'Low':
            rec_frame = tk.Frame(results_container, bg='#fdf2f2', relief='solid', bd=1)
            rec_frame.pack(fill='x', padx=20, pady=(10, 20))
            
            tk.Label(rec_frame, text="Recommendations:", font=('Arial', 10, 'bold'),
                    fg='#c53030', bg='#fdf2f2').pack(anchor='w', padx=10, pady=(10, 5))
            
            recommendations = [
                "• Do not enter personal or financial information on this site.",
                "• Verify the domain name carefully before proceeding.",
                "• Close the browser tab immediately.",
                "• Consider reporting this URL to your IT department or relevant authorities."
            ]
            
            for rec in recommendations:
                tk.Label(rec_frame, text=rec, font=('Arial', 9), fg='#c53030',
                        bg='#fdf2f2', justify='left').pack(anchor='w', padx=20, pady=1)
            
            tk.Label(rec_frame, text="", bg='#fdf2f2').pack(pady=2)  # Spacer

def main():
    try:
        import matplotlib
        matplotlib.use('TkAgg')  # Set backend before importing pyplot
    except ImportError:
        messagebox.showerror("Dependency Error", 
                             "Matplotlib is required for charts.\nPlease install it using: pip install matplotlib")
        return
    
    root = tk.Tk()
    app = PhishingDetectionDashboard(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication closed by user.")

if __name__ == "__main__":
    main()
