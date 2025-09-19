import unittest
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from lambda_function import EmailVerifier, lambda_handler


class TestEmailVerifier(unittest.TestCase):
    
    def setUp(self):
        self.verifier = EmailVerifier()
    
    def test_valid_email_format(self):
        valid_emails = [
            'john.doe@gmail.com',
            'user+tag@example.co.uk',
            'test.email.123@company.com',
            'valid_email@domain.org'
        ]
        for email in valid_emails:
            result = self.verifier.verify_email(email)
            self.assertTrue(result['is_valid_format'], f"Failed for: {email}")

    def test_invalid_email_format(self):
        invalid_emails = [
            'notanemail',
            '@example.com',
            'user@',
            'user@@example.com',
            'user@domain',
            'user @example.com',
            ''
        ]
        for email in invalid_emails:
            result = self.verifier.verify_email(email)
            self.assertFalse(result['is_valid_format'], f"Should fail for: {email}")
    
    def test_disposable_email_detection(self):
        disposable_emails = [
            'test@tempmail.com',
            'user@guerrillamail.com',
            'temp@10minutemail.com',
            'fake@mailinator.com'
        ]
        for email in disposable_emails:
            result = self.verifier.verify_email(email)
            self.assertTrue(result['is_disposable'], f"Should detect disposable: {email}")
    
    def test_legitimate_email_not_disposable(self):
        legitimate_emails = [
            'user@gmail.com',
            'contact@company.com',
            'admin@microsoft.com'
        ]
        for email in legitimate_emails:
            result = self.verifier.verify_email(email)
            self.assertFalse(result['is_disposable'], f"Should not flag as disposable: {email}")
    
    def test_role_based_detection(self):
        role_emails = [
            'admin@example.com',
            'support@company.com',
            'noreply@service.com',
            'info@business.com'
        ]
        for email in role_emails:
            result = self.verifier.verify_email(email)
            self.assertTrue(result['is_role_based'], f"Should detect role-based: {email}")
    
    def test_suspicious_pattern_detection(self):
        suspicious_emails = [
            'test12345678@example.com',  # 8+ digits
            'testuser@example.com',       # starts with 'test'
            'spammer@example.com',        # contains 'spam'
            'fake.email@example.com'      # contains 'fake'
        ]
        for email in suspicious_emails:
            result = self.verifier.verify_email(email)
            self.assertTrue(result['is_suspicious'], f"Should detect suspicious: {email}")
    
    def test_lambda_handler_success(self):
        event = {
            'email': 'test@gmail.com'
        }
        context = {}

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 200)
        body = json.loads(response['body'])
        self.assertEqual(body['email'], 'test@gmail.com')
        self.assertIn('is_valid_format', body)

    def test_lambda_handler_api_gateway_format(self):
        event = {
            'body': json.dumps({'email': 'test@example.com'})
        }
        context = {}
        
        response = lambda_handler(event, context)
        
        self.assertEqual(response['statusCode'], 200)
        body = json.loads(response['body'])
        self.assertEqual(body['email'], 'test@example.com')
    
    def test_lambda_handler_missing_email(self):
        event = {}
        context = {}

        response = lambda_handler(event, context)

        self.assertEqual(response['statusCode'], 400)
        body = json.loads(response['body'])
        self.assertIn('error', body)
    
if __name__ == '__main__':
    unittest.main()