import unittest
from unittest.mock import MagicMock, patch
import hashlib
from bs4 import BeautifulSoup
import requests

# Import the classes from your main script
# Assuming the main file is named sqlinjection_scanner.py
from cli import FormParser, SQLInjectionScanner

class TestFormParser(unittest.TestCase):
    """Test cases for the FormParser class"""
    
    def setUp(self):
        # Create a mock session
        self.mock_session = MagicMock()
        self.form_parser = FormParser(self.mock_session)
        
    def test_get_all_forms(self):
        """Test getting all forms from a URL"""
        # Create a mock response with HTML content
        mock_response = MagicMock()
        html_content = """
        <html>
            <form action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            <form action="/search" method="get">
                <input type="text" name="query">
                <input type="submit" value="Search">
            </form>
        </html>
        """
        mock_response.content = html_content.encode()
        self.mock_session.get.return_value = mock_response
        
        # Test getting forms
        forms = self.form_parser.get_all_forms("http://example.com")
        
        # Assertions
        self.assertEqual(len(forms), 2)
        self.mock_session.get.assert_called_once_with("http://example.com")
        
    def test_get_form_details(self):
        """Test extracting details from a form"""
        # Create a test form
        html = """
        <form action="/login" method="post">
            <input type="text" name="username" value="">
            <input type="password" name="password">
            <input type="hidden" name="csrf" value="token123">
            <input type="submit" value="Login">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        
        # Test getting form details
        details = self.form_parser.get_form_details(form)
        
        # Assertions
        self.assertEqual(details["action"], "/login")
        self.assertEqual(details["method"], "post")
        self.assertEqual(len(details["inputs"]), 4)
        
        # Check input details
        input_names = [inp["name"] for inp in details["inputs"] if inp["name"]]
        self.assertIn("username", input_names)
        self.assertIn("password", input_names)
        self.assertIn("csrf", input_names)
        
        # Check hidden input
        hidden_input = next(inp for inp in details["inputs"] if inp["type"] == "hidden")
        self.assertEqual(hidden_input["name"], "csrf")
        self.assertEqual(hidden_input["value"], "token123")


class TestSQLInjectionScanner(unittest.TestCase):
    """Test cases for the SQLInjectionScanner class"""
    
    def setUp(self):
        # Create scanner without DB dependency
        self.scanner = SQLInjectionScanner()
        # Create a patch for requests.Session
        self.session_patcher = patch('requests.Session')
        self.mock_session_class = self.session_patcher.start()
        self.mock_session = self.mock_session_class.return_value
        self.scanner.session = self.mock_session
        
    def tearDown(self):
        self.session_patcher.stop()
        
    def test_is_vulnerable(self):
        """Test vulnerability detection in response"""
        # Create a mock response with SQL error
        mock_response = MagicMock()
        mock_response.content = b"You have an error in your SQL syntax; check the manual"
        
        # Test vulnerability detection
        result = self.scanner.is_vulnerable(mock_response)
        
        # Assertions
        self.assertTrue(result)
        
        # Test with non-vulnerable response
        mock_response.content = b"This is a normal response with no SQL errors"
        result = self.scanner.is_vulnerable(mock_response)
        self.assertFalse(result)
        
    @patch.object(SQLInjectionScanner, '_test_url_injection')
    @patch.object(SQLInjectionScanner, '_test_form_injection')
    def test_scan_url(self, mock_test_form, mock_test_url):
        """Test full URL scanning process"""
        # Configure mocks
        mock_test_url.return_value = True  # URL injection found
        mock_test_form.return_value = False  # No form injection
        
        # Test scan
        result = self.scanner.scan_url("http://example.com")
        
        # Assertions
        self.assertTrue(result)
        mock_test_url.assert_called_once_with("http://example.com")
        mock_test_form.assert_called_once_with("http://example.com")
        
    def test_test_url_injection(self):
        """Test URL parameter injection"""
        # Configure mock responses
        vulnerable_response = MagicMock()
        vulnerable_response.content = b"You have an error in your SQL syntax;"
        
        safe_response = MagicMock()
        safe_response.content = b"Normal response"
        
        # Set up mock to return different responses for different URLs
        def mock_get(url):
            if "'" in url:  # Vulnerable with single quote
                return vulnerable_response
            return safe_response
            
        self.mock_session.get.side_effect = mock_get
        
        # Test URL injection
        result = self.scanner._test_url_injection("http://example.com/page.php?id=1")
        
        # Assertions
        self.assertTrue(result)
        self.assertEqual(len(self.scanner.vulnerabilities_found), 1)
        self.assertIn("SQL Injection vulnerability detected", self.scanner.vulnerabilities_found[0])


# Main test runner
if __name__ == '__main__':
    unittest.main()