from django.urls import path
from . import views

app_name = 'video_app'

urlpatterns = [
    # Web interface
    path('', views.video_player, name='player'),
    
    # API endpoints
    path('api/register-device/', views.register_device, name='register_device'),
    path('api/request-stream/', views.request_video_stream, name='request_stream'),
    path('api/complete-key-exchange/', views.complete_key_exchange, name='complete_key_exchange'),
    path('api/videos/', views.list_videos, name='list_videos'),
      # Video streaming
    path('api/video/manifest/<str:session_id>/', views.get_video_manifest, name='video_manifest'),
    path('api/video/stream/<str:session_id>/<int:segment_number>/', views.stream_video_segment, name='video_segment'),
    
    # Debug/test endpoints
    path('api/test/video/<int:video_id>/', views.test_video_file, name='test_video'),
    path('api/demo/encryption/<int:video_id>/', views.show_encryption_demo, name='encryption_demo'),
    path('api/demo/security/<str:session_id>/', views.show_session_security, name='session_security'),
    path('api/demo/protection/', views.show_piracy_protection_demo, name='protection_demo'),
    path('api/demo/jwt-security/', views.demo_jwt_security, name='jwt_security_demo'),
    
    # Forensic watermarking endpoints
    path('api/demo/watermark/<str:session_id>/', views.show_forensic_watermark_demo, name='watermark_demo'),
    path('api/verify-watermark/', views.verify_forensic_watermark, name='verify_watermark'),
]
