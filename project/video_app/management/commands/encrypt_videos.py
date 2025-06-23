from django.core.management.base import BaseCommand
from video_app.models import Video
from video_app.crypto_utils import ContentEncryption, VideoProcessor
import os

class Command(BaseCommand):
    help = 'Encrypt video files and show the difference'

    def handle(self, *args, **options):
        videos = Video.objects.all()
        
        for video in videos:
            original_path = video.original_file_path
            encrypted_path = original_path.replace('.mp4', '_encrypted.bin')
            
            if os.path.exists(original_path):
                # Generate a sample CEK for encryption
                cek = ContentEncryption.generate_cek()
                
                self.stdout.write(f"Encrypting {video.title}...")
                self.stdout.write(f"Original file: {original_path}")
                self.stdout.write(f"Encrypted file: {encrypted_path}")
                self.stdout.write(f"CEK (hex): {cek.hex()}")
                
                # Encrypt the video
                VideoProcessor.encrypt_video_file(original_path, encrypted_path, cek)
                
                # Update video model
                video.encrypted_file_path = encrypted_path
                video.is_processed = True
                video.save()
                
                # Show file sizes for comparison
                original_size = os.path.getsize(original_path)
                encrypted_size = os.path.getsize(encrypted_path)
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Encryption complete!\n"
                        f"Original size: {original_size:,} bytes\n"
                        f"Encrypted size: {encrypted_size:,} bytes\n"
                        f"Overhead: {encrypted_size - original_size:,} bytes"
                    )
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f"Video file not found: {original_path}")
                )
