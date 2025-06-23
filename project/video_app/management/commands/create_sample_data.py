from django.core.management.base import BaseCommand
from video_app.models import Video
import os

class Command(BaseCommand):
    help = 'Create sample video data for testing'

    def handle(self, *args, **options):
        # Check if example.mp4 exists
        video_path = os.path.join('video_app', 'example.mp4')
        
        if not os.path.exists(video_path):
            self.stdout.write(
                self.style.WARNING(f'Video file not found at {video_path}')
            )
            return
        
        # Create or update the video entry
        video, created = Video.objects.get_or_create(
            title='Example Video',
            defaults={
                'description': 'A sample video for testing the secure streaming system',
                'original_file_path': video_path,
                'duration_seconds': 120,  # 2 minutes
                'is_processed': False
            }
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created video: {video.title}')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Video already exists: {video.title}')
            )
        
        self.stdout.write(
            self.style.SUCCESS(f'Video ID: {video.id}')
        )
