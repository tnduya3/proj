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
from .security_utils import ForensicWatermarking

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
    
    @staticmethod
    def decrypt_video_chunk(encrypted_data, cek):
        """Decrypt video chunk with CEK using AES-GCM"""
        # Extract components
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        encrypted_chunk = encrypted_data[28:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(cek), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt chunk
        decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
        return decrypted_chunk

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
    """Handle video processing, DASH packaging, and forensic watermarking"""
    
    @staticmethod
    def encrypt_video_file_with_watermark(input_path, output_path, cek, user_token, device_fingerprint, session_id):
        """
        Encrypt video file with embedded forensic watermark containing user identification
        
        Args:
            input_path (str): Path to original video file
            output_path (str): Path for encrypted output file
            cek (bytes): Content Encryption Key
            user_token (str): User JWT token for watermarking
            device_fingerprint (str): Device fingerprint hash
            session_id (str): Streaming session ID
        """
        chunk_size = 1024 * 1024  # 1MB chunks
        
        # Generate forensic watermark
        watermark_payload = ForensicWatermarking.generate_watermark_payload(
            user_token, device_fingerprint, session_id
        )
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            chunk_index = 0
            
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                
                # Apply forensic watermarking to chunk
                if chunk_index == 0:
                    # Embed metadata watermark in first chunk
                    chunk = ForensicWatermarking.embed_watermark_in_video_metadata(chunk, watermark_payload)
                
                # Apply steganographic watermarking (every 10th chunk to avoid detection)
                if chunk_index % 10 == 0:
                    chunk = ForensicWatermarking.embed_steganographic_watermark(
                        chunk, watermark_payload['binary_data'], intensity=1
                    )
                
                # Encrypt the watermarked chunk
                encrypted_chunk = ContentEncryption.encrypt_video_chunk(chunk, cek)
                
                # Write chunk size + encrypted chunk
                outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                outfile.write(encrypted_chunk)
                
                chunk_index += 1
        
        return watermark_payload

    @staticmethod
    def encrypt_video_file(input_path, output_path, cek):
        """Encrypt entire video file with CEK (legacy method without watermarking)"""
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
    def decrypt_and_verify_watermark(encrypted_file_path, cek, expected_watermark_hash):
        """
        Decrypt video file and verify forensic watermark for piracy detection
        
        Args:
            encrypted_file_path (str): Path to encrypted video file
            cek (bytes): Content Encryption Key
            expected_watermark_hash (str): Expected watermark hash for verification
            
        Returns:
            dict: Verification results including watermark status
        """
        try:
            with open(encrypted_file_path, 'rb') as infile:
                # Read and decrypt first chunk to check watermark
                chunk_size_bytes = infile.read(4)
                if len(chunk_size_bytes) < 4:
                    return {'verified': False, 'error': 'Invalid file format'}
                
                chunk_size = int.from_bytes(chunk_size_bytes, 'big')
                encrypted_chunk = infile.read(chunk_size)
                
                # Decrypt first chunk
                decrypted_chunk = ContentEncryption.decrypt_video_chunk(encrypted_chunk, cek)
                
                # Extract watermark from metadata
                watermark_info = ForensicWatermarking.extract_watermark_from_metadata(decrypted_chunk)
                
                if watermark_info['found']:
                    verification_result = {
                        'verified': True,
                        'watermark_hash': watermark_info['watermark_hash'],
                        'matches_expected': watermark_info['watermark_hash'] == expected_watermark_hash,
                        'extraction_method': watermark_info['extraction_method']
                    }
                else:
                    verification_result = {
                        'verified': False,
                        'error': watermark_info.get('error', 'Watermark not found')
                    }
                
                return verification_result
                
        except Exception as e:
            return {'verified': False, 'error': str(e)}

    @staticmethod
    def create_session_hash(session_data):
        """Create hash for session identification"""
        return hashlib.sha256(session_data.encode()).hexdigest()
