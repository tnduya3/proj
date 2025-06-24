#!/usr/bin/env python
"""
Clean up duplicate devices from the database
"""
import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')
django.setup()

from video_app.models import Device
import hashlib

def clean_duplicate_devices():
    """Remove duplicate devices and ensure fingerprint_hash is set"""
    print("🧹 Cleaning up duplicate devices...")
    
    # Get all devices
    all_devices = Device.objects.all()
    print(f"📊 Total devices found: {all_devices.count()}")
    
    # Track unique fingerprints
    seen_fingerprints = {}
    devices_to_delete = []
    devices_to_update = []
    
    for device in all_devices:
        # Generate fingerprint if missing
        if not device.fingerprint_hash:
            fingerprint_data = f"{device.user_agent}|{device.screen_resolution}|{device.timezone_offset}|{device.language}"
            device.fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            devices_to_update.append(device)
        
        # Check for duplicates
        if device.fingerprint_hash in seen_fingerprints:
            # Mark for deletion (keep the first one)
            devices_to_delete.append(device)
            print(f"🗑️  Marking duplicate device for deletion: {device.device_id}")
        else:
            seen_fingerprints[device.fingerprint_hash] = device
            print(f"✅ Keeping device: {device.device_id} (fingerprint: {device.fingerprint_hash[:16]}...)")
    
    # Update devices with missing fingerprint_hash
    if devices_to_update:
        print(f"🔄 Updating {len(devices_to_update)} devices with missing fingerprint hashes...")
        for device in devices_to_update:
            device.save()
    
    # Delete duplicate devices
    if devices_to_delete:
        print(f"🗑️  Deleting {len(devices_to_delete)} duplicate devices...")
        Device.objects.filter(id__in=[d.id for d in devices_to_delete]).delete()
    
    # Final count
    final_count = Device.objects.count()
    print(f"✅ Cleanup complete! Final device count: {final_count}")
    
    return final_count

if __name__ == "__main__":
    clean_duplicate_devices()
