"""
Cryptographic utilities for secure video streaming
"""
import os
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import jwt
from datetime import datetime, timedelta
from django.conf import settings

class DiffieHellmanKeyExchange:
    """Handle Diffie-Hellman key exchange for secure communication"""
    
    def __init__(self):
        # Use a simplified approach for demo purposes
        # In production, you'd use proper DH parameters
        pass
    
    def generate_server_keypair(self):
        """Generate server's DH key pair (simplified for demo)"""
        # Generate random server private key
        server_private = secrets.token_hex(32)
        
        # Generate corresponding public key (simplified)
        server_public = hashlib.sha256(server_private.encode()).hexdigest()
        
        return server_private, server_public
    
    def compute_shared_secret(self, server_private_key, client_public_key):
        """Compute shared secret (simplified for demo)"""
        # Simplified shared secret computation
        combined = server_private_key + client_public_key
        shared_secret = hashlib.sha256(combined.encode()).digest()
        
        # Derive session key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=b'video-streaming-salt',
            info=b'video-streaming-session',
            backend=default_backend()
        ).derive(shared_secret)
        
        return derived_key

class ContentEncryption:
    """Handle content encryption and decryption"""
    
    @staticmethod
    def generate_cek():
        """Generate a new Content Encryption Key (CEK)"""
        return secrets.token_bytes(32)  # 256-bit AES key
    
    @staticmethod
    def encrypt_cek_with_session_key(cek, session_key):
        """Encrypt CEK with DH session key"""
        # Generate random IV
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
        
        # Create cipher
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt CEK
        encrypted_cek = encryptor.update(cek) + encryptor.finalize()
        
        # Return IV + tag + encrypted_cek
        return iv + encryptor.tag + encrypted_cek
    
    @staticmethod
    def decrypt_cek_with_session_key(encrypted_data, session_key):
        """Decrypt CEK with DH session key"""
        # Extract components
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        encrypted_cek = encrypted_data[28:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt CEK
        cek = decryptor.update(encrypted_cek) + decryptor.finalize()
        return cek
    
    @staticmethod
    def encrypt_video_chunk(chunk_data, cek):
        """Encrypt video chunk with CEK using AES-GCM"""
        # Generate random IV for each chunk
        iv = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(cek), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt chunk
        encrypted_chunk = encryptor.update(chunk_data) + encryptor.finalize()
        
        # Return IV + tag + encrypted_chunk
        return iv + encryptor.tag + encrypted_chunk

class DeviceFingerprinting:
    """Handle device fingerprinting and token generation"""
    
    @staticmethod
    def generate_device_token(fingerprint_hash):
        """Generate JWT token for device authentication"""
        payload = {
            'device_fingerprint': fingerprint_hash,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
        }
        
        token = jwt.encode(
            payload,
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        
        return token
    
    @staticmethod
    def verify_device_token(token):
        """Verify and decode device token"""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

class VideoProcessor:
    """Handle video processing and DASH packaging"""
    
    @staticmethod
    def encrypt_video_file(input_path, output_path, cek):
        """Encrypt entire video file with CEK"""
        chunk_size = 1024 * 1024  # 1MB chunks
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                
                encrypted_chunk = ContentEncryption.encrypt_video_chunk(chunk, cek)
                # Write chunk size + encrypted chunk
                outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                outfile.write(encrypted_chunk)
    
    @staticmethod
    def create_session_hash(session_data):
        """Create hash for session identification"""
        return hashlib.sha256(session_data.encode()).hexdigest()
