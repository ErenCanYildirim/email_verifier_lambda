import json
import re
import dns.resolver
from datetime import datetime
from typing import Dict

class EmailVerifier:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

        self.disposable_domains = {
            'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'mailinator.com',
            '10minutemail.com', 'throwaway.email', 'maildrop.cc', 'yopmail.com',
            'trashmail.com', 'sharklasers.com', 'guerrillamail.info', 'grr.la',
            'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.net', 
            'guerrillamail.org', 'guerrillamailblock.com', 'pokemail.net',
            'spam4.me', 'tempr.email', 'fakeinbox.com', 'mailnesia.com',
            'mintemail.com', 'mytemp.email', 'temp-mail.io', 'mohmal.com',
            'emailondeck.com', 'gmailnator.com', 'dispostable.com', 'throwawaymail.com',
            'tmail.ws', 'getnada.com', 'temp-link.net', 'tmpmail.org',
            'burnermail.io', 'emailfake.com', 'spambox.us', 'anonymmail.net'
        }

        self.role_based_prefixes = {
            'admin', 'administrator', 'webmaster', 'hostmaster', 'postmaster',
            'noreply', 'no-reply', 'support', 'sales', 'info', 'contact',
            'marketing', 'abuse', 'security', 'privacy', 'help', 'billing',
            'accounts', 'service', 'newsletter', 'notifications', 'alerts',
            'mailer-daemon', 'daemon', 'root', 'system', 'bot', 'automated'
        }

        self.suspicious_patterns = [
            r'\d{8,}',
            r'^test',   
            r'test$',   
            r'^temp',   
            r'spam',    
            r'fake',    
            r'throwaway',
            r'disposable',
            r'delete',
            r'remove'
        ]

    def verify_email(self, email: str) -> Dict[str, any]:
        result = {
            'email': email,
            'is_valid_format': False,
            'domain_exists': False,
            'has_mx_records': False,
            'is_disposable': False,
            'is_role_based': False,
            'is_suspicious': False,
            'is_free_provider': False,
            'deliverable': False,
            'safe_to_register': False,
            'errors': [],
            'warnings': []
        }

        if not self._is_valid_format(email):
            result['errors'].append('Invalid email format')
            return result
        result['is_valid_format'] = True

        local_part, domain = email.lower().split('@')

        if self._is_disposable_email(domain):
            result['is_disposable'] = True
            result['errors'].append('Disposable/temporary email detected')
        
        if self._is_role_based_email(local_part):
            result['is_role_based'] = True
            result['warnings'].append('Role-based email address')
        
        if self._has_suspicious_pattern(email):
            result['is_suspicious'] = True
            result['warnings'].append('Suspicious email pattern detected')

        result['is_free_provider'] = self._is_free_provider(domain)

        if not self._domain_exists(domain):
            result['errors'].append('Domain does not exist')
            return result
        result['domain_exists'] = True

        mx_records = self._get_mx_records(domain)
        if not mx_records:
            result['errors'].append('No MX records found')
            return result
        result['has_mx_records'] = True

        result['deliverable'] = (
            result['is_valid_format'] and 
            result['domain_exists'] and 
            result['has_mx_records']
        )

        result['safe_to_register'] = (
            result['deliverable'] and 
            not result['is_disposable'] and 
            not result['is_suspicious']
        )

        return result

    def _is_valid_format(self, email: str) -> bool:
        if len(email) < 4 or len(email) > 320:
            return False
        
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*[a-zA-Z0-9]@[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return re.match(pattern, email.lower()) is not None

    def _is_disposable_email(self, domain: str) -> bool:
        domain = domain.lower()
        return domain in self.disposable_domains

    def _is_role_based_email(self, local_part: str) -> bool:
        local_part = local_part.lower()
        return local_part in self.role_based_prefixes

    def _has_suspicious_pattern(self, email: str) -> bool:
        email_lower = email.lower()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, email_lower):
                return True
        return False

    def _is_free_provider(self, domain: str) -> bool:
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'mail.com', 'protonmail.com', 'gmx.com', 'zoho.com',
            'yandex.com', 'live.com', 'msn.com', 'googlemail.com', 'me.com'
        }
        return domain.lower() in free_providers

    def _domain_exists(self, domain: str) -> bool:
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except:
            return True
    
    def _get_mx_records(self, domain: str) -> list:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(r.exchange).rstrip('.') for r in sorted(mx_records, key=lambda x: x.preference)]
        except:
            return []

def lambda_handler(event, context):
    """
    AWS Lambda handler function
    
    Expected input format:
    {
        "email": "test@example.com"
    }
    or
    {
        "body": "{\"email\": \"test@example.com\"}"  // For API Gateway
    }
    """

    try:
        if 'body' in event:
            body = json.loads(event['body'])
            email = body.get('email')
        else:
            email = event.get('email')
    
        if not email:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origins': '*'
                },
                'body': json.dumps({
                    'error': 'Email parameter is required'
                })
            }

        verifier = EmailVerifier()
        result = verifier.verify_email(email)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(result)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e)
            })
        }