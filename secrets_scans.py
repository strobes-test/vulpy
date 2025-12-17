"""
Vulnerable Python code containing hardcoded secrets for GitHub Secret Scanning
This file contains intentional secret leaks for testing purposes
"""

import requests
from sqlalchemy import create_engine

# Hardcoded API Key
API_KEY = "my-super-secret-api-key-12345-do-not-share"

# Database Connection String with hardcoded password
DATABASE_URL = "postgresql://admin:SuperSecretP@ssw0rd!@production-db.example.com:5432/maindb"

# JWT Secret Key
JWT_SECRET = "jwt-super-secret-token-67890-keep-this-private"


def create_db_connection():
    """Create database connection with hardcoded credentials"""
    engine = create_engine(
        "postgresql://admin:SuperSecretP@ssw0rd!@production-db.example.com:5432/maindb"
    )
    return engine


def make_api_request():
    """Make API request with hardcoded key"""
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    response = requests.get('https://api.example.com/data', headers=headers)
    return response.json()


if __name__ == "__main__":
    print("This file contains hardcoded secrets for testing purposes only!")

