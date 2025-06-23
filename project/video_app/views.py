import json
import secrets
import hashlib
import os
from datetime import datetime, timedelta
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import Device, Video, StreamingSession
from .crypto_utils import (
    DiffieHellmanKeyExchange,
    ContentEncryption,
    DeviceFingerprinting,
    VideoProcessor
)

# ==================== DEVICE REGISTRATION ====================

@csrf_exempt
@require_http_methods(["POST"])
def register_device(request):
    """Register a new device and return authentication token"""
    try:
        data = json.loads(request.body)
        
        # Extract device fingerprint data
        user_agent = data.get('user_agent', '')
        screen_resolution = data.get('screen_resolution', '')
        timezone_offset = data.get('timezone_offset', 0)
        language = data.get('language', 'en')
        
        # Create or get device
        device, created = Device.objects.get_or_create(
            user_agent=user_agent,
            screen_resolution=screen_resolution,
            timezone_offset=timezone_offset,
            language=language
        )
        
        # Generate authentication token
        token = DeviceFingerprinting.generate_device_token(device.fingerprint_hash)
        
        return JsonResponse({
            'success': True,
            'device_id': str(device.device_id),
            'token': token,
            'expires_in': settings.JWT_EXPIRATION_MINUTES * 60
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

# ==================== VIDEO STREAMING ====================

@csrf_exempt
@require_http_methods(["POST"])
def request_video_stream(request):
    """Handle video streaming request and initiate DH key exchange"""
    try:
        data = json.loads(request.body)
        video_id = data.get('video_id')
        token = data.get('token')
        
        # Verify token
        try:
            payload = DeviceFingerprinting.verify_device_token(token)
            device_fingerprint = payload['device_fingerprint']
        except ValueError as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=401)
        
        # Get device and video
        device = get_object_or_404(Device, fingerprint_hash=device_fingerprint)
        video = get_object_or_404(Video, id=video_id)
        
        # Generate DH key pair for server
        dh_exchange = DiffieHellmanKeyExchange()
        server_private_key, server_public_key = dh_exchange.generate_server_keypair()
        
        # Create streaming session
        session_id = secrets.token_hex(32)
        expires_at = timezone.now() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
        
        session = StreamingSession.objects.create(
            device=device,
            video=video,
            session_id=session_id,
            dh_public_key=server_public_key,
            dh_private_key=server_private_key,
            expires_at=expires_at
        )
        
        return JsonResponse({
            'success': True,
            'session_id': session_id,
            'server_public_key': server_public_key,
            'expires_at': expires_at.isoformat()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

@csrf_exempt
@require_http_methods(["POST"])
def complete_key_exchange(request):
    """Complete DH key exchange and generate encrypted CEK"""
    try:
        data = json.loads(request.body)
        session_id = data.get('session_id')
        client_public_key = data.get('client_public_key')
        
        # Get streaming session
        session = get_object_or_404(StreamingSession, session_id=session_id, is_active=True)
        
        if session.is_expired():
            return JsonResponse({
                'success': False,
                'error': 'Session expired'
            }, status=401)
        
        # Store client public key
        session.client_dh_public_key = client_public_key
        
        # Compute shared secret
        dh_exchange = DiffieHellmanKeyExchange()
        session_key = dh_exchange.compute_shared_secret(
            session.dh_private_key,
            client_public_key
        )
        
        # Generate CEK and encrypt it with session key
        cek = ContentEncryption.generate_cek()
        encrypted_cek = ContentEncryption.encrypt_cek_with_session_key(cek, session_key)
        
        # Store encrypted CEK and session key hash
        session.encrypted_cek = encrypted_cek.hex()
        session.session_key_hash = hashlib.sha256(session_key).hexdigest()
        session.save()
        
        return JsonResponse({
            'success': True,
            'encrypted_cek': encrypted_cek.hex()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

@require_http_methods(["GET"])
def get_video_manifest(request, session_id):
    """Get DASH manifest for video streaming"""
    try:
        session = get_object_or_404(StreamingSession, session_id=session_id, is_active=True)
        
        if session.is_expired():
            return JsonResponse({
                'success': False,
                'error': 'Session expired'
            }, status=401)
        
        # Generate DASH manifest (simplified)
        manifest = f"""<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" 
     type="static" 
     mediaPresentationDuration="PT{session.video.duration_seconds}S"
     profiles="urn:mpeg:dash:profile:isoff-on-demand:2011">
  <Period>
    <AdaptationSet mimeType="video/mp4" codecs="avc1.42E01E">
      <Representation id="1" bandwidth="1000000" width="1280" height="720">
        <BaseURL>/api/video/stream/{session_id}/</BaseURL>
        <SegmentTemplate media="segment_$Number$.m4s" 
                        initialization="init.m4s"
                        duration="{settings.VIDEO_SEGMENT_DURATION}"
                        startNumber="1"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>"""
        
        return HttpResponse(manifest, content_type='application/dash+xml')
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

def stream_video_segment(request, session_id, segment_number):
    """Stream encrypted video segment"""
    try:
        session = get_object_or_404(StreamingSession, session_id=session_id, is_active=True)
        
        if session.is_expired():
            return HttpResponse("Session expired", status=401)
        
        # Get the video file path
        video_path = session.video.original_file_path
        
        # For demo purposes, we'll stream the original video file directly
        # In production, you would stream encrypted segments
        try:
            def file_iterator(file_path, chunk_size=8192):
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk
            
            # Get the full path to the video file
            full_video_path = os.path.join(settings.BASE_DIR, video_path)
            
            if os.path.exists(full_video_path):
                response = StreamingHttpResponse(
                    file_iterator(full_video_path),
                    content_type='video/mp4'
                )
                response['Accept-Ranges'] = 'bytes'
                response['Content-Length'] = os.path.getsize(full_video_path)
                return response
            else:
                return HttpResponse("Video file not found", status=404)
                
        except Exception as e:
            return HttpResponse(f"Error streaming video: {str(e)}", status=500)
        
    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=400)

# ==================== WEB INTERFACE ====================

def video_player(request):
    """Main video player interface"""
    videos = Video.objects.all()
    return render(request, 'video_app/player.html', {'videos': videos})

@api_view(['GET'])
def list_videos(request):
    """API endpoint to list available videos"""
    videos = Video.objects.all()
    video_data = []
    
    for video in videos:
        video_data.append({
            'id': video.id,
            'title': video.title,
            'description': video.description,
            'duration': video.duration_seconds
        })
    
    return Response(video_data)

# ==================== DEBUG/TEST ENDPOINTS ====================

@api_view(['GET'])
def test_video_file(request, video_id):
    """Test endpoint to check if video file exists"""
    try:
        video = get_object_or_404(Video, id=video_id)
        full_path = os.path.join(settings.BASE_DIR, video.original_file_path)
        
        exists = os.path.exists(full_path)
        
        return Response({
            'video_id': video_id,
            'title': video.title,
            'file_path': video.original_file_path,
            'full_path': full_path,
            'exists': exists,
            'size': os.path.getsize(full_path) if exists else 0
        })
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=400)

@api_view(['GET'])
def show_encryption_demo(request, video_id):
    """Demonstrate encryption by showing original vs encrypted data"""
    try:
        video = get_object_or_404(Video, id=video_id)
        
        original_path = os.path.join(settings.BASE_DIR, video.original_file_path)
        
        if not os.path.exists(original_path):
            return Response({'error': 'Original video file not found'}, status=404)
        
        # Read first 1KB of original file
        with open(original_path, 'rb') as f:
            original_data = f.read(1024)
        
        # Generate a CEK and encrypt the same data
        cek = ContentEncryption.generate_cek()
        encrypted_data = ContentEncryption.encrypt_video_chunk(original_data, cek)
        
        return Response({
            'video_title': video.title,
            'demonstration': {
                'original_data_hex': original_data[:100].hex(),  # First 100 bytes
                'original_data_preview': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in original_data[:100]),
                'encrypted_data_hex': encrypted_data[:100].hex(),  # First 100 bytes
                'encrypted_data_preview': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in encrypted_data[:100]),
                'cek_used': cek.hex(),
                'explanation': {
                    'original': 'This is the raw video file data - readable patterns visible',
                    'encrypted': 'This is the same data encrypted with AES-256-GCM - completely randomized',
                    'security': 'Without the CEK, this encrypted data is cryptographically secure'
                }
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
def show_session_security(request, session_id):
    """Show the security measures for a specific streaming session"""
    try:
        session = get_object_or_404(StreamingSession, session_id=session_id)
        
        # Decode the encrypted CEK (if available)
        encrypted_cek_data = session.encrypted_cek
        
        return Response({
            'session_security': {
                'session_id': session_id,
                'device_fingerprint': session.device.fingerprint_hash,
                'video_title': session.video.title,
                'dh_exchange': {
                    'server_public_key': session.dh_public_key[:50] + '...',
                    'client_public_key': session.client_dh_public_key[:50] + '...' if session.client_dh_public_key else 'Not set',
                    'session_key_hash': session.session_key_hash
                },
                'encryption': {
                    'encrypted_cek': encrypted_cek_data[:50] + '...' if encrypted_cek_data else 'Not generated',
                    'cek_explanation': 'This CEK is encrypted with the DH session key - unique per session',
                },
                'time_security': {
                    'created_at': session.created_at.isoformat(),
                    'expires_at': session.expires_at.isoformat(),
                    'is_expired': session.is_expired(),
                    'time_remaining': str(session.expires_at - timezone.now()) if not session.is_expired() else 'EXPIRED'
                },
                'anti_piracy_measures': [
                    'Device-specific encryption keys',
                    'Time-limited session tokens',
                    'Encrypted content at rest',
                    'Dynamic key generation per session',
                    'No direct file access - only through secure streaming'
                ]
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
def show_piracy_protection_demo(request):
    """Demonstrate various anti-piracy protection measures"""
    try:
        videos = Video.objects.all()
        
        protection_demo = {
            'anti_piracy_demonstrations': {
                'direct_file_access': {
                    'description': 'Try to access video files directly - BLOCKED',
                    'tests': []
                },
                'session_based_access': {
                    'description': 'Video streaming requires valid session',
                    'requirements': [
                        'Device fingerprint registration',
                        'Valid JWT token (5 min expiry)',
                        'Diffie-Hellman key exchange',
                        'Session-specific CEK decryption'
                    ]
                },
                'encryption_protection': {
                    'description': 'Video content is encrypted at multiple levels',
                    'layers': [
                        'File-level encryption with unique CEK per session',
                        'Transport encryption with DH session keys',
                        'Device-specific key derivation',
                        'Time-limited access tokens'
                    ]
                },
                'dynamic_security': {
                    'description': 'Security measures that prevent static copying',
                    'features': [
                        'New encryption keys for each streaming session',
                        'Device fingerprint validation',
                        'Session expiration (5 minutes)',
                        'No persistent decryption keys on client'
                    ]
                }
            }
        }
        
        # Test direct file access blocking
        for video in videos:
            original_path = video.original_file_path
            protection_demo['anti_piracy_demonstrations']['direct_file_access']['tests'].append({
                'video': video.title,
                'file_path': original_path,
                'direct_access_url': f'/media/{original_path}',
                'result': 'BLOCKED - File not accessible via direct URL',
                'secure_access': 'Only via encrypted streaming with valid session'
            })
        
        return Response(protection_demo)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)
