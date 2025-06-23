from django.db import models
from django.utils import timezone
import hashlib
import json
import uuid

class Video(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    # Path to the unencrypted video file (for server-side processing)
    original_file_path = models.CharField(max_length=500)
    # Path to the encrypted video file 
    encrypted_file_path = models.CharField(max_length=500, blank=True)
    # Path to the DASH manifest file (.mpd)
    dash_manifest_path = models.CharField(max_length=500, blank=True, null=True)
    duration_seconds = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    is_processed = models.BooleanField(default=False)

    def __str__(self):
        return self.title

class Device(models.Model):
    """Store device fingerprints for authentication"""
    device_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    fingerprint_hash = models.CharField(max_length=64, unique=True)
    user_agent = models.TextField()
    screen_resolution = models.CharField(max_length=50)
    timezone_offset = models.IntegerField()
    language = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.fingerprint_hash:
            # Generate fingerprint hash from device characteristics
            fingerprint_data = {
                'user_agent': self.user_agent,
                'screen_resolution': self.screen_resolution,
                'timezone_offset': self.timezone_offset,
                'language': self.language
            }
            fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
            self.fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Device {self.fingerprint_hash[:8]}..."

class StreamingSession(models.Model):
    """Track active streaming sessions with encryption keys"""
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    video = models.ForeignKey(Video, on_delete=models.CASCADE)
    session_id = models.CharField(max_length=64, unique=True)
    
    # Diffie-Hellman key exchange
    dh_public_key = models.TextField()  # Server's DH public key
    dh_private_key = models.TextField()  # Server's DH private key (encrypted)
    client_dh_public_key = models.TextField(blank=True)  # Client's DH public key
    session_key_hash = models.CharField(max_length=64, blank=True)  # Hash of shared secret
    
    # Content Encryption Key (CEK)
    encrypted_cek = models.TextField(blank=True)  # CEK encrypted with DH session key
    
    # Session management
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Session {self.session_id[:8]}... for {self.device}"