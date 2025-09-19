import unittest
import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

class TestEmailVerifierAPI(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up test configuration"""
        # Get from environment variables
        cls.api_url = os.getenv('PROD_API_URL')
        cls.api_key = os.getenv('PROD_API_KEY')
        cls.test_api_url = os.getenv('TEST_API_URL')
        cls.test_api_key = os.getenv('TEST_API_KEY')
        
        if not cls.api_key:
            raise ValueError("API_KEY environment variable not set")
    
    def _make_request(self, email, use_test=False):
        """Helper method to make API request"""
        url = self.test_api_url if use_test else self.api_url
        api_key = self.test_api_key if use_test else self.api_key
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key
        }
        payload = {"email": email}
        
        response = requests.post(url, headers=headers, json=payload)
        return response
    
    def _parse_response(self, response):
        """Parse the nested API Gateway response"""
        if response.status_code == 200:
            data = response.json()
            # API Gateway returns body as a JSON string
            if 'body' in data:
                return json.loads(data['body'])
            return data
        return response.json()
    
    def test_api_authentication_required(self):
        """Test that API requires authentication"""
        url = self.api_url
        headers = {"Content-Type": "application/json"}  # No API key
        payload = {"email": "test@gmail.com"}
        
        response = requests.post(url, headers=headers, json=payload)
        self.assertEqual(response.status_code, 403)  # Forbidden
    
    def test_valid_email_via_api(self):
        """Test valid email through API"""
        response = self._make_request("john.doe@gmail.com")
        self.assertEqual(response.status_code, 200)
        
        data = self._parse_response(response)
        self.assertEqual(data['email'], 'john.doe@gmail.com')
        self.assertTrue(data['is_valid_format'])
        self.assertTrue(data['is_free_provider'])
    
    def test_disposable_email_via_api(self):
        """Test disposable email detection via API"""
        response = self._make_request("test@tempmail.com")
        self.assertEqual(response.status_code, 200)
        
        data = self._parse_response(response)
        self.assertTrue(data['is_disposable'])
        self.assertFalse(data['safe_to_register'])
    
    def test_invalid_format_via_api(self):
        """Test invalid email format via API"""
        response = self._make_request("notanemail")
        self.assertEqual(response.status_code, 200)
        
        data = self._parse_response(response)
        self.assertFalse(data['is_valid_format'])
        self.assertIn('Invalid email format', data.get('errors', []))
    
    def test_role_based_email_via_api(self):
        """Test role-based email via API"""
        response = self._make_request("admin@example.com")
        self.assertEqual(response.status_code, 200)
        
        data = self._parse_response(response)
        self.assertTrue(data['is_role_based'])
    
    def test_missing_email_parameter(self):
        """Test API with missing email parameter"""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key
        }
        
        response = requests.post(self.api_url, headers=headers, json={})
        # API returns 200 with error message in body, not 400
        # This is how your Lambda is configured
        self.assertEqual(response.status_code, 200)
        
        data = self._parse_response(response)
        self.assertIn('error', data)

if __name__ == '__main__':
    unittest.main()