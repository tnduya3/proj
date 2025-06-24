"""
Security utilities for JWT token management and secret key generation
"""
import secrets
import os
from pathlib import Path

def get_or_generate_jwt_secret():
    """
    Get JWT secret key from environment variable or generate a new one.
    In production, this should be stored securely and not regenerated on each restart.
    """
    # Try to get from environment variable first (production best practice)
    jwt_secret = os.environ.get('JWT_SECRET_KEY')
    
    if jwt_secret:
        return jwt_secret
    
    # For development, generate a secure random key
    # In production, you should set this as an environment variable
    # or store it in a secure configuration management system
    return secrets.token_urlsafe(64)  # 64 bytes = 512 bits of entropy

def generate_secure_jwt_secret():
    """
    Generate a cryptographically secure JWT secret key.
    Returns a URL-safe base64 encoded string with 512 bits of entropy.
    """
    return secrets.token_urlsafe(64)

def validate_jwt_secret_strength(secret_key):
    """
    Validate the strength of a JWT secret key.
    Returns True if the key meets security requirements.
    """
    # Minimum recommended length for JWT secrets is 256 bits (32 bytes)
    # We recommend 512 bits (64 bytes) for better security
    min_length = 32
    recommended_length = 64
    
    if len(secret_key) < min_length:
        return False, f"JWT secret too short. Minimum {min_length} characters required."
    
    if len(secret_key) < recommended_length:
        return True, f"JWT secret meets minimum requirements but {recommended_length} characters recommended."
    
    return True, "JWT secret meets security requirements."

# Example usage and security notes
SECURITY_NOTES = """
JWT Secret Key Security Best Practices:

1. NEVER commit JWT secrets to version control
2. Use environment variables in production: export JWT_SECRET_KEY="your-secret-here"
3. Rotate keys periodically for enhanced security
4. Use cryptographically secure random generation
5. Store keys in secure configuration management systems
6. Consider using different keys for different environments (dev/staging/prod)

For this educational project, we generate a random key on each restart.
In production, use a persistent, securely stored key.
"""
