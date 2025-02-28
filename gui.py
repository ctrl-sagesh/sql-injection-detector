import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import sys
import io
from datetime import datetime

# Import the classes from the original tool
from cli import Database, FormParser, SQLInjectionScanner

class RedirectText:
    """Class to redirect stdout to a tkinter Text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = io.StringIO()

    def write(self, string):
        self.buffer.write(string)
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")
        
    def flush(self):
        pass

class SQLInjectionScannerGUI:
    """GUI for the SQL Injection Scanner"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        self.db = Database()
        self.current_user_id = None
        self.scanner = None
        
        # Create the main notebook with tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create login frame
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="Login")
        self.setup_login_frame()
        
        # Create register frame
        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text="Register")
        self.setup_register_frame()
        
        # Create scanner frame
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="Scanner")
        self.setup_scanner_frame()
        
        # Create history frame
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="History")
        self.setup_history_frame()
        
        # Disable tabs until login
        self.notebook.tab(2, state="disabled")
        self.notebook.tab(3, state="disabled")
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Not logged in")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Styling
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("TLabel", padding=6)
        style.configure("TEntry", padding=6)
        
    def setup_login_frame(self):
        """Setup the login frame with its widgets"""
        frame = ttk.Frame(self.login_frame, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="Login to SQL Injection Scanner", font=("Arial", 16))
        title_label.pack(pady=20)
        
        # Username field
        username_frame = ttk.Frame(frame)
        username_frame.pack(fill=tk.X, pady=5)
        username_label = ttk.Label(username_frame, text="Username:", width=15)
        username_label.pack(side=tk.LEFT)
        self.login_username = ttk.Entry(username_frame)
        self.login_username.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Password field
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill=tk.X, pady=5)
        password_label = ttk.Label(password_frame, text="Password:", width=15)
        password_label.pack(side=tk.LEFT)
        self.login_password = ttk.Entry(password_frame, show="*")
        self.login_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Login button
        login_button = ttk.Button(frame, text="Login", command=self.login)
        login_button.pack(pady=20)
        
    def setup_register_frame(self):
        """Setup the register frame with its widgets"""
        frame = ttk.Frame(self.register_frame, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text="Register New Account", font=("Arial", 16))
        title_label.pack(pady=20)
        
        # Username field
        username_frame = ttk.Frame(frame)
        username_frame.pack(fill=tk.X, pady=5)
        username_label = ttk.Label(username_frame, text="Username:", width=15)
        username_label.pack(side=tk.LEFT)
        self.register_username = ttk.Entry(username_frame)
        self.register_username.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Password field
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill=tk.X, pady=5)
        password_label = ttk.Label(password_frame, text="Password:", width=15)
        password_label.pack(side=tk.LEFT)
        self.register_password = ttk.Entry(password_frame, show="*")
        self.register_password.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Confirm password field
        confirm_frame = ttk.Frame(frame)
        confirm_frame.pack(fill=tk.X, pady=5)
        confirm_label = ttk.Label(confirm_frame, text="Confirm Password:", width=15)
        confirm_label.pack(side=tk.LEFT)
        self.register_confirm = ttk.Entry(confirm_frame, show="*")
        self.register_confirm.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Email field
        email_frame = ttk.Frame(frame)
        email_frame.pack(fill=tk.X, pady=5)
        email_label = ttk.Label(email_frame, text="Email (optional):", width=15)
        email_label.pack(side=tk.LEFT)
        self.register_email = ttk.Entry(email_frame)
        self.register_email.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Register button
        register_button = ttk.Button(frame, text="Register", command=self.register)
        register_button.pack(pady=20)
        
    def setup_scanner_frame(self):
        """Setup the scanner frame with its widgets"""
        frame = ttk.Frame(self.scanner_frame, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # URL entry frame
        url_frame = ttk.Frame(frame)
        url_frame.pack(fill=tk.X, pady=10)
        
        url_label = ttk.Label(url_frame, text="URL to scan:")
        url_label.pack(side=tk.LEFT)
        
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/artists.php?artist=1")
        
        scan_button = ttk.Button(url_frame, text="Scan", command=self.start_scan)
        scan_button.pack(side=tk.LEFT)
        
        # Output area
        output_frame = ttk.LabelFrame(frame, text="Scan Results")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state="disabled")
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout to the text widget
        self.stdout_redirect = RedirectText(self.output_text)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, pady=10)
        
    def setup_history_frame(self):
        """Setup the history frame with its widgets"""
        frame = ttk.Frame(self.history_frame, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Refresh button
        refresh_button = ttk.Button(frame, text="Refresh History", command=self.load_history)
        refresh_button.pack(pady=10)
        
        # Treeview for scan history
        columns = ("url", "time", "status", "details")
        self.history_tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        # Define headings
        self.history_tree.heading("url", text="URL")
        self.history_tree.heading("time", text="Scan Time")
        self.history_tree.heading("status", text="Status")
        self.history_tree.heading("details", text="Details")
        
        # Define columns
        self.history_tree.column("url", width=200)
        self.history_tree.column("time", width=150)
        self.history_tree.column("status", width=100)
        self.history_tree.column("details", width=300)
        
        self.history_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def login(self):
        """Handle user login"""
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        user_id = self.db.login_user(username, password)
        if user_id:
            self.current_user_id = user_id
            self.scanner = SQLInjectionScanner(user_id, self.db)
            
            # Enable scanner and history tabs
            self.notebook.tab(2, state="normal")
            self.notebook.tab(3, state="normal")
            
            # Switch to scanner tab
            self.notebook.select(2)
            
            # Update status bar
            self.status_var.set(f"Logged in as: {username}")
            
            # Load scan history
            self.load_history()
            
            messagebox.showinfo("Success", f"Welcome {username}!")
        else:
            messagebox.showerror("Error", "Invalid username or password")
            
    def register(self):
        """Handle user registration"""
        username = self.register_username.get()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        email = self.register_email.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        success = self.db.register_user(username, password, email)
        if success:
            messagebox.showinfo("Success", f"User '{username}' registered successfully")
            # Clear fields
            self.register_username.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_confirm.delete(0, tk.END)
            self.register_email.delete(0, tk.END)
            # Switch to login tab
            self.notebook.select(0)
        else:
            messagebox.showerror("Error", "Registration failed")
            
    def start_scan(self):
        """Start a scan in a separate thread to keep UI responsive"""
        if not self.scanner:
            messagebox.showerror("Error", "You must be logged in to scan")
            return
            
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "URL is required")
            return
            
        # Clear previous output
        self.output_text.configure(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state="disabled")
        
        # Start progress bar animation
        self.progress_var.set(0)
        self.progress.start()
        
        # Redirect stdout to the text widget
        old_stdout = sys.stdout
        sys.stdout = self.stdout_redirect
        
        # Start scan in a thread
        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.daemon = True
        thread.start()
        
        # Schedule check for completion
        self.root.after(100, lambda: self.check_scan_complete(thread, old_stdout))
        
    def run_scan(self, url):
        """Run the actual scan in a separate thread"""
        try:
            self.scanner.scan_url(url)
        except Exception as e:
            print(f"[!] Error during scan: {e}")
            
    def check_scan_complete(self, thread, old_stdout):
        """Check if scan thread is complete"""
        if thread.is_alive():
            # Check again in 100ms
            self.root.after(100, lambda: self.check_scan_complete(thread, old_stdout))
        else:
            # Scan complete, stop progress and restore stdout
            self.progress.stop()
            self.progress_var.set(100)
            sys.stdout = old_stdout
            
            # Reload history
            self.load_history()
            
    def load_history(self):
        """Load scan history into the history tree"""
        if not self.current_user_id:
            return
            
        # Clear previous items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Get history from database
        history = self.db.get_user_scan_history(self.current_user_id)
        
        # Add items to tree
        for record in history:
            status = "VULNERABLE" if record['vulnerable'] else "SECURE"
            details = record['vulnerability_details'] if record['vulnerability_details'] else ""
            
            # Truncate details if too long
            if details and len(details) > 100:
                details = details[:100] + "..."
                
            self.history_tree.insert("", tk.END, values=(
                record['url'],
                record['scan_time'],
                status,
                details
            ))


if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionScannerGUI(root)
    root.mainloop()