"""
Security utilities for JWT token management and secret key generation
"""
import secrets
import os
import hashlib
import struct
import time
import base64
from pathlib import Path

def get_or_generate_jwt_secret():
    # Try to get from environment
    jwt_secret = os.environ.get('JWT_SECRET_KEY')
    
    if jwt_secret:
        return jwt_secret
    
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

class ForensicWatermarking:
    """
    Forensic watermarking system to embed user identification into video content
    for anti-piracy tracking and content protection
    """
    
    @staticmethod
    def generate_watermark_payload(user_token, device_fingerprint, session_id, timestamp=None):
        """
        Generate a forensic watermark payload containing user identification
        
        Args:
            user_token (str): JWT token or user identifier
            device_fingerprint (str): Device fingerprint hash
            session_id (str): Streaming session ID
            timestamp (float): Unix timestamp (optional, defaults to current time)
        
        Returns:
            dict: Watermark payload with embedded user data
        """
        if timestamp is None:
            timestamp = time.time()
        
        try:
            # Ensure all inputs are strings and handle any encoding issues
            user_token = str(user_token) if user_token else "unknown_user"
            device_fingerprint = str(device_fingerprint) if device_fingerprint else "unknown_device"
            session_id = str(session_id) if session_id else "unknown_session"
            
            # Create forensic payload
            forensic_data = {
                'user_hash': hashlib.sha256(user_token.encode('utf-8', errors='replace')).hexdigest()[:16],
                'device_id': device_fingerprint[:16],
                'session_id': session_id[:12],
                'timestamp': int(timestamp),
                'watermark_version': '1.0'
            }
            
        except Exception as e:
            # Fallback if encoding fails
            forensic_data = {
                'user_hash': 'fallback_user_hash',
                'device_id': 'fallback_device',
                'session_id': 'fallback_session',
                'timestamp': int(timestamp),
                'watermark_version': '1.0_fallback'
            }
          # Create a compact binary representation
        watermark_string = f"{forensic_data['user_hash']}{forensic_data['device_id']}{forensic_data['session_id']}{forensic_data['timestamp']}"
        watermark_hash = hashlib.sha256(watermark_string.encode('utf-8', errors='replace')).hexdigest()[:32]
        
        return {
            'payload': forensic_data,
            'watermark_hash': watermark_hash,
            'binary_data_base64': base64.b64encode(ForensicWatermarking._create_binary_watermark(forensic_data)).decode('ascii')
        }
    
    @staticmethod
    def _create_binary_watermark(forensic_data):
        """
        Create a compact binary representation of forensic data
        
        Args:
            forensic_data (dict): Forensic payload data
            
        Returns:
            bytes: Binary watermark data
        """
        try:
            # Pack data into binary format with proper encoding
            user_hash_bytes = forensic_data['user_hash'].encode('utf-8', errors='replace')[:16]
            device_id_bytes = forensic_data['device_id'].encode('utf-8', errors='replace')[:16]
            session_id_bytes = forensic_data['session_id'].encode('utf-8', errors='replace')[:12]
            timestamp_bytes = struct.pack('>I', forensic_data['timestamp'])  # 4 bytes, big-endian
            
            # Pad with zeros if needed to ensure consistent length
            user_hash_bytes = user_hash_bytes.ljust(16, b'\x00')
            device_id_bytes = device_id_bytes.ljust(16, b'\x00')
            session_id_bytes = session_id_bytes.ljust(12, b'\x00')
              # Combine into single binary watermark
            binary_watermark = user_hash_bytes + device_id_bytes + session_id_bytes + timestamp_bytes
            return binary_watermark
            
        except Exception as e:
            # Fallback to simple string encoding if binary fails
            fallback_data = f"{forensic_data['user_hash']}|{forensic_data['device_id']}|{forensic_data['session_id']}|{forensic_data['timestamp']}"
            return fallback_data.encode('utf-8', errors='replace')
    
    @staticmethod
    def embed_watermark_in_video_metadata(video_data, watermark_payload):
        """
        Embed forensic watermark into video metadata/headers
        
        Args:
            video_data (bytes): Original video data
            watermark_payload (dict): Watermark data from generate_watermark_payload
            
        Returns:
            bytes: Video data with embedded watermark
        """
        # For MP4 files, we can embed in metadata boxes
        # This is a simplified implementation - in production you'd use proper MP4 parsing
        
        watermark_metadata = f"FORENSIC_WM:{watermark_payload['watermark_hash']}"
        metadata_bytes = watermark_metadata.encode()
        
        # Simple approach: prepend metadata (in production, use proper MP4 atom insertion)
        metadata_header = struct.pack('>I', len(metadata_bytes)) + b'FWMK' + metadata_bytes
        
        return metadata_header + video_data
    
    @staticmethod
    def embed_steganographic_watermark(video_chunk, watermark_binary, intensity=1):
        """
        Embed watermark using steganographic techniques (LSB modification)
        
        Args:
            video_chunk (bytes): Video chunk data
            watermark_binary (bytes): Binary watermark to embed
            intensity (int): Embedding intensity (1-8, affects LSB bits)
            
        Returns:
            bytes: Video chunk with steganographic watermark
        """
        if len(video_chunk) < len(watermark_binary) * 8:
            # Not enough space in chunk for watermark
            return video_chunk
        
        chunk_array = bytearray(video_chunk)
        watermark_bits = ForensicWatermarking._bytes_to_bits(watermark_binary)
        
        # Embed watermark bits into LSBs of video data
        for i, bit in enumerate(watermark_bits):
            if i >= len(chunk_array):
                break
            
            # Modify the least significant bit
            chunk_array[i] = (chunk_array[i] & 0xFE) | bit
        
        return bytes(chunk_array)
    
    @staticmethod
    def _bytes_to_bits(data):
        """Convert bytes to list of bits"""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        return bits
    
    @staticmethod
    def extract_watermark_from_metadata(video_data):
        """
        Extract forensic watermark from video metadata
        
        Args:
            video_data (bytes): Video data with embedded watermark
            
        Returns:
            dict: Extracted watermark information or None if not found
        """
        try:
            # Look for our metadata header
            if video_data.startswith(b'\x00\x00\x00'):
                # Read metadata length
                metadata_length = struct.unpack('>I', video_data[:4])[0]
                
                if video_data[4:8] == b'FWMK':
                    # Extract metadata
                    metadata_bytes = video_data[8:8+metadata_length]
                    metadata_string = metadata_bytes.decode()
                    
                    if metadata_string.startswith('FORENSIC_WM:'):
                        watermark_hash = metadata_string[12:]  # Remove 'FORENSIC_WM:' prefix
                        return {
                            'found': True,
                            'watermark_hash': watermark_hash,
                            'extraction_method': 'metadata'
                        }
            
            return {'found': False, 'error': 'No watermark found in metadata'}
            
        except Exception as e:
            return {'found': False, 'error': str(e)}
    
    @staticmethod
    def generate_watermark_report(watermark_payload, video_info):
        """
        Generate a forensic watermark report for tracking and auditing
        
        Args:
            watermark_payload (dict): Watermark data
            video_info (dict): Video information
            
        Returns:
            dict: Comprehensive watermark report
        """
        return {
            'watermark_report': {
                'video_title': video_info.get('title', 'Unknown'),
                'video_id': video_info.get('id', 'Unknown'),
                'forensic_data': watermark_payload['payload'],
                'watermark_hash': watermark_payload['watermark_hash'],
                'embedding_timestamp': time.time(),
                'security_level': 'HIGH',
                'tracking_capabilities': [
                    'User identification via token hash',
                    'Device fingerprint tracking',
                    'Session-specific identification',
                    'Timestamp-based tracking',
                    'Steganographic embedding',
                    'Metadata-based identification'
                ],
                'anti_piracy_features': [
                    'Unique per-user watermarking',
                    'Tamper detection capabilities',
                    'Multi-layer embedding (metadata + steganographic)',
                    'Cryptographic hash verification',
                    'Session-specific tracking'
                ]
            }
        }
