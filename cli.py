import argparse
import requests
import mysql.connector
import hashlib
import getpass
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pprint import pprint
from datetime import datetime
import os
import time


class Database:
    """Class to handle database operations"""
    
    def __init__(self, host="localhost", user="root", password="", database="sqlinjection_scanner"):
        self.config = {
            "host": host,
            "user": user,
            "password": password,
            "database": database
        }
        self.connection = None
        self.setup_database()
        
    def connect(self):
        """Connect to the database"""
        try:
            self.connection = mysql.connector.connect(**self.config)
            return self.connection
        except mysql.connector.Error as err:
            print(f"[!] Database connection error: {err}")
            return None
            
    def setup_database(self):
        """Create the database and tables if they don't exist"""
        try:
            # First connect without specifying a database
            temp_config = self.config.copy()
            temp_config.pop("database", None)
            conn = mysql.connector.connect(**temp_config)
            cursor = conn.cursor()
            
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
            cursor.close()
            conn.close()
            
            # Now connect to the database and create tables
            connection = self.connect()
            if connection:
                cursor = connection.cursor()
                
                # Create users table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(128) NOT NULL,
                    email VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """)
                
                # Create scan_history table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    url VARCHAR(255) NOT NULL,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    vulnerable BOOLEAN DEFAULT FALSE,
                    vulnerability_details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
                """)
                
                connection.commit()
                cursor.close()
                connection.close()
                print(f"[+] Database '{self.config['database']}' setup successfully")
            
        except mysql.connector.Error as err:
            print(f"[!] Database setup error: {err}")
            
    def register_user(self, username, password, email=None):
        """Register a new user"""
        connection = self.connect()
        if not connection:
            return False
            
        cursor = connection.cursor()
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                print(f"[!] User '{username}' already exists")
                cursor.close()
                connection.close()
                return False
                
            # Insert new user
            if email:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)",
                    (username, password_hash, email)
                )
            else:
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, password_hash)
                )
                
            connection.commit()
            print(f"[+] User '{username}' registered successfully")
            cursor.close()
            connection.close()
            return True
            
        except mysql.connector.Error as err:
            print(f"[!] Registration error: {err}")
            connection.close()
            return False
            
    def login_user(self, username, password):
        """Authenticate a user and return user ID if successful"""
        connection = self.connect()
        if not connection:
            return None
            
        cursor = connection.cursor()
        
        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            # Check credentials
            cursor.execute(
                "SELECT id FROM users WHERE username = %s AND password_hash = %s",
                (username, password_hash)
            )
            result = cursor.fetchone()
            
            cursor.close()
            connection.close()
            
            if result:
                return result[0]  # Return user ID
            else:
                print("[!] Invalid username or password")
                return None
                
        except mysql.connector.Error as err:
            print(f"[!] Login error: {err}")
            connection.close()
            return None
            
    def log_scan(self, user_id, url, vulnerable, details=None):
        """Log a scan to the history"""
        connection = self.connect()
        if not connection:
            return False
            
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO scan_history (user_id, url, vulnerable, vulnerability_details) VALUES (%s, %s, %s, %s)",
                (user_id, url, vulnerable, details)
            )
            connection.commit()
            cursor.close()
            connection.close()
            return True
            
        except mysql.connector.Error as err:
            print(f"[!] Error logging scan: {err}")
            connection.close()
            return False
            
    def get_user_scan_history(self, user_id):
        """Get scan history for a user"""
        connection = self.connect()
        if not connection:
            return []
            
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.execute(
                "SELECT url, scan_time, vulnerable, vulnerability_details FROM scan_history WHERE user_id = %s ORDER BY scan_time DESC",
                (user_id,)
            )
            results = cursor.fetchall()
            
            cursor.close()
            connection.close()
            return results
            
        except mysql.connector.Error as err:
            print(f"[!] Error fetching scan history: {err}")
            connection.close()
            return []


class FormParser:
    """Class to handle HTML form parsing operations"""
    
    def __init__(self, session):
        self.session = session
    
    def get_all_forms(self, url):
        """Get all forms from a given URL"""
        response = self.session.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    
    def get_form_details(self, form):
        """Extract useful information from an HTML form"""
        details = {}
        
        # Get the form action (target URL)
        try:
            action = form.attrs.get("action", "").lower()
        except AttributeError:
            action = None
            
        # Get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        
        # Get all input details
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type, 
                "name": input_name, 
                "value": input_value
            })
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details


class SQLInjectionScanner:
    """Class to handle SQL injection scanning operations"""
    
    def __init__(self, user_id=None, db=None):
        # Initialize HTTP session & set the browser
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        self.form_parser = FormParser(self.session)
        self.user_id = user_id
        self.db = db
        self.vulnerabilities_found = []
        
        # SQL error signatures
        self.sql_errors = {
            # MySQL
            "you have an error in your sql syntax;",
            "warning: mysql",
            # SQL Server
            "unclosed quotation mark after the character string",
            # Oracle
            "quoted string not properly terminated",
            # PostgreSQL
            "syntax error at or near",
            # SQLite
            "sqlite3.operationalerror:"
        }
    
    def is_vulnerable(self, response):
        """Determine if a page is vulnerable from its response"""
        if not response or not response.content:
            return False
            
        content = response.content.decode().lower()
        return any(error in content for error in self.sql_errors)
    
    def scan_url(self, url):
        """Scan a URL for SQL injection vulnerabilities"""
        print(f"[*] Starting SQL injection scan for: {url}")
        self.vulnerabilities_found = []
        vulnerable = False
        
        # Test URL injection
        print("[*] Testing URL parameter injection...")
        if self._test_url_injection(url):
            vulnerable = True
        
        # Test form injection
        print("[*] Testing form injection...")
        if self._test_form_injection(url):
            vulnerable = True
            
        # Log the scan in database if connected
        if self.db and self.user_id:
            details = None
            if self.vulnerabilities_found:
                details = "\n".join(self.vulnerabilities_found)
            self.db.log_scan(self.user_id, url, vulnerable, details)
            
        return vulnerable
    
    def _test_url_injection(self, url):
        """Test URL parameters for SQL injection"""
        found_vulnerable = False
        for char in "\"'":
            test_url = f"{url}{char}"
            print(f"[!] Trying {test_url}")
            
            try:
                response = self.session.get(test_url)
                if self.is_vulnerable(response):
                    vulnerability = f"SQL Injection vulnerability detected in URL: {test_url}"
                    print(f"[+] {vulnerability}")
                    self.vulnerabilities_found.append(vulnerability)
                    found_vulnerable = True
            except requests.RequestException as e:
                print(f"[!] Request error: {e}")
        
        return found_vulnerable
    
    def _test_form_injection(self, url):
        """Test forms for SQL injection"""
        found_vulnerable = False
        try:
            forms = self.form_parser.get_all_forms(url)
            print(f"[+] Detected {len(forms)} forms on {url}")
            
            for i, form in enumerate(forms):
                if self._test_single_form(url, form, i):
                    found_vulnerable = True
                
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            
        return found_vulnerable
    
    def _test_single_form(self, url, form, form_index):
        """Test a single form for SQL injection"""
        form_details = self.form_parser.get_form_details(form)
        found_vulnerable = False
        
        for char in "\"'":
            # Prepare the data to submit
            data = {}
            for input_tag in form_details["inputs"]:
                # Skip if input has no name
                if not input_tag["name"]:
                    continue
                    
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # Use existing values for hidden fields
                    try:
                        data[input_tag["name"]] = input_tag["value"] + char
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # Use test data for other fields
                    data[input_tag["name"]] = f"test{char}"
            
            # Join URL with form action
            form_url = urljoin(url, form_details["action"]) if form_details["action"] else url
            
            try:
                if form_details["method"] == "post":
                    response = self.session.post(form_url, data=data)
                else:  # Default to GET
                    response = self.session.get(form_url, params=data)
                
                # Check if the result indicates vulnerability
                if self.is_vulnerable(response):
                    vulnerability = f"SQL Injection vulnerability detected in form #{form_index+1} at URL: {form_url}"
                    print(f"[+] {vulnerability}")
                    print("[+] Form details:")
                    pprint(form_details)
                    
                    # Add to vulnerabilities list
                    self.vulnerabilities_found.append(vulnerability)
                    form_details_str = str(form_details)
                    self.vulnerabilities_found.append(f"Form details: {form_details_str}")
                    
                    found_vulnerable = True
            except requests.RequestException as e:
                print(f"[!] Request error: {e}")
                
        return found_vulnerable


class CLI:
    """Command-line interface for the SQL Injection Scanner"""
    
    def __init__(self):
        self.db = Database()
        self.current_user_id = None
        self.scanner = None
        
    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_header(self):
        """Print the application header"""
        self.clear_screen()
        print("=" * 60)
        print("            SQL INJECTION SCANNER")
        print("=" * 60)
        print()
        
    def print_menu(self):
        """Print the main menu"""
        self.print_header()
        
        if self.current_user_id:
            print("1. Scan a URL")
            print("2. View scan history")
            print("3. Logout")
            print("0. Exit")
        else:
            print("1. Login")
            print("2. Register")
            print("0. Exit")
            
        print()
        return input("Select an option: ")
        
    def register(self):
        """Register a new user"""
        self.print_header()
        print("===== USER REGISTRATION =====")
        
        username = input("Username: ")
        if not username:
            print("[!] Username cannot be empty")
            input("Press Enter to continue...")
            return
            
        password = getpass.getpass("Password: ")
        if not password:
            print("[!] Password cannot be empty")
            input("Press Enter to continue...")
            return
            
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("[!] Passwords do not match")
            input("Press Enter to continue...")
            return
            
        email = input("Email (optional): ")
        
        self.db.register_user(username, password, email)
        input("Press Enter to continue...")
        
    def login(self):
        """Login a user"""
        self.print_header()
        print("===== USER LOGIN =====")
        
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        user_id = self.db.login_user(username, password)
        if user_id:
            self.current_user_id = user_id
            self.scanner = SQLInjectionScanner(user_id, self.db)
            print(f"[+] Welcome {username}!")
        
        input("Press Enter to continue...")
        
    def logout(self):
        """Logout the current user"""
        self.current_user_id = None
        self.scanner = None
        print("[+] Logged out successfully")
        input("Press Enter to continue...")
        
    def scan_url(self):
        """Scan a URL for SQL injection vulnerabilities"""
        self.print_header()
        print("===== SCAN URL =====")
        
        url = input("Enter the URL to scan (e.g., http://testphp.vulnweb.com/artists.php?artist=1): ")
        if not url:
            url = "http://testphp.vulnweb.com/artists.php?artist=1"
            print(f"[*] Using default URL: {url}")
            
        print("\nScanning, please wait...\n")
        self.scanner.scan_url(url)
        
        input("\nPress Enter to continue...")
        
    def view_history(self):
        """View scan history for the current user"""
        self.print_header()
        print("===== SCAN HISTORY =====")
        
        history = self.db.get_user_scan_history(self.current_user_id)
        
        if not history:
            print("[!] No scan history found")
        else:
            print(f"Found {len(history)} scan records:\n")
            for i, record in enumerate(history):
                status = "VULNERABLE" if record['vulnerable'] else "SECURE"
                print(f"{i+1}. URL: {record['url']}")
                print(f"   Time: {record['scan_time']}")
                print(f"   Status: {status}")
                if record['vulnerable'] and record['vulnerability_details']:
                    print(f"   Details: {record['vulnerability_details'][:100]}...")
                print()
        
        input("Press Enter to continue...")
        
    def run(self):
        """Run the CLI interface"""
        while True:
            choice = self.print_menu()
            
            if self.current_user_id:  # User is logged in
                if choice == "1":
                    self.scan_url()
                elif choice == "2":
                    self.view_history()
                elif choice == "3":
                    self.logout()
                elif choice == "0":
                    print("[+] Goodbye!")
                    break
            else:  # User is not logged in
                if choice == "1":
                    self.login()
                elif choice == "2":
                    self.register()
                elif choice == "0":
                    print("[+] Goodbye!")
                    break


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner with User Management")
    parser.add_argument("--host", default="localhost", help="Database host (default: localhost)")
    parser.add_argument("--user", default="root", help="Database user (default: root)")
    parser.add_argument("--password", default="", help="Database password (default: empty)")
    parser.add_argument("--db", default="sqlinjection_scanner", help="Database name (default: sqlinjection_scanner)")
    
    args = parser.parse_args()
    
    # Override the default database settings if provided
    if any([args.host != "localhost", args.user != "root", args.password != "", args.db != "sqlinjection_scanner"]):
        db = Database(args.host, args.user, args.password, args.db)
    else:
        # Use default settings
        db = None
    
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()