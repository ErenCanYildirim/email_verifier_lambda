# Email Verifier API Documentation

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange.svg)

An email verification API that validates email addresses, detects disposable/temporary emails, and checks for suspicious patterns. Built individually instead of using apis for this and deployed as a serverless Lambda function. Developed for user registration, form validation, and email list cleaning.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Request Format](#request-format)
- [Response Format](#response-format)
- [Error Handling](#error-handling)
- [Rate Limits](#rate-limits)
- [Code Examples](#code-examples)

## Overview

The Email Verifier API provides comprehensive email validation including:

    - Format validation
    - Domain resolving
    - MX record check
    - Disposable/temporary email detection
    - Role-based email detection (e.g. admin, info etc)
    - suspicious patterns check via regex

**Base URLS:**
    - Production and Test

## Quick start

### make request
```bash
    curl -X POST <aws:url>
        -H "Content-Type: application/json" \
        -H "x-api-key: API_KEY" \
        -d '{"email": "user@example.com"}'
```

### response 
```json
    {
        "email": "user@example.com",
        "is_valid_format": true,
        "domain_exists": true,
        "has_mx_records": true,
        "is_disposable": false,
        "safe_to_register": true 
    }
```

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | The email address verified |
| `is_valid_format` | boolean | Email has valid format |
| `domain_exists` | boolean | Domain exists in DNS |
| `has_mx_records` | boolean | Domain can receive emails |
| `is_disposable` | boolean | Disposable email service |
| `is_role_based` | boolean | Role-based email (admin@, support@) |
| `is_suspicious` | boolean | Suspicious patterns detected |
| `deliverable` | boolean | Email can receive messages |
| `safe_to_register` | boolean | Safe for user registration |

## Deployment Guide

## Prerequisites

    - AWS account and keys
    - API Gateway setup

## Step 1 -> deploy lambda func

```bash
    pip install -r lambda_requirements.txt -t package/

    cp lambda_function.py package/

    #create deployment package
    cd package
    zip -r ../lambda_function.zip
    cd ..

    #deploy to lambda
```
## Step 2 -> create API GW

    1. Create REST API via API Gateway
    2. create /verify resource
    3. add post method and api keys
    4. deploy to prod/test and perhaps staging
    5. create api key and usage plan
    6. add api keys to different stages

## Testing

Includes unit tests and integration tests
Run via:
```bash
    pytest tests/test_email_verifier.py -v 

    pytest tests/test_integration.py -v 
```

## License

MIT License
