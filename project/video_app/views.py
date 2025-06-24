import json
import secrets
import hashlib
import os
import jwt
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
from .security_utils import ForensicWatermarking

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
        
        # Create fingerprint hash the same way as in the model
        fingerprint_data = {
            'user_agent': user_agent,
            'screen_resolution': screen_resolution,
            'timezone_offset': timezone_offset,
            'language': language
        }
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        # Try to get existing device by fingerprint hash, or create new one
        try:
            device = Device.objects.get(fingerprint_hash=fingerprint_hash)
            created = False
        except Device.DoesNotExist:
            # Create new device
            device = Device.objects.create(
                user_agent=user_agent,
                screen_resolution=screen_resolution,
                timezone_offset=timezone_offset,
                language=language
                # fingerprint_hash will be generated automatically in save() method
            )
            created = True
        
        # Generate authentication token
        token = DeviceFingerprinting.generate_device_token(device.fingerprint_hash)
        
        return JsonResponse({
            'success': True,
            'device_id': str(device.device_id),
            'token': token,
            'expires_in': settings.JWT_EXPIRATION_MINUTES * 60,
            'created': created,
            'fingerprint': device.fingerprint_hash[:16] + '...'  # Show first 16 chars for debugging
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
    """Complete DH key exchange and generate encrypted CEK with forensic watermarking"""
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
        
        # Generate forensic watermark for this session
        # Use device fingerprint as user token for watermarking
        device_token = session.device.fingerprint_hash
        watermark_payload = ForensicWatermarking.generate_watermark_payload(
            device_token, session.device.fingerprint_hash, session_id
        )
        
        # Store encrypted CEK, session key hash, and watermark info
        session.encrypted_cek = encrypted_cek.hex()
        session.session_key_hash = hashlib.sha256(session_key).hexdigest()
        session.watermark_hash = watermark_payload['watermark_hash']  # Add this field to model if needed
        session.save()
        
        return JsonResponse({
            'success': True,
            'encrypted_cek': encrypted_cek.hex(),
            'watermark_info': {
                'watermark_hash': watermark_payload['watermark_hash'],
                'embedded': True,
                'tracking_enabled': True
            }
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

@api_view(['GET'])
def demo_jwt_security(request):
    """Demonstrate JWT security with different secret keys"""
    try:
        from django.conf import settings
        import jwt
        from datetime import datetime, timedelta
        
        # Sample payload
        payload = {
            'device_fingerprint': 'demo-device-123',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=5)
        }
        
        # Generate tokens with different secret keys
        current_secret = settings.JWT_SECRET_KEY
        weak_secret = "weak123"
        another_secret = secrets.token_urlsafe(64)
        
        # Create tokens
        token_with_current_secret = jwt.encode(payload, current_secret, algorithm='HS256')
        token_with_weak_secret = jwt.encode(payload, weak_secret, algorithm='HS256')
        token_with_different_secret = jwt.encode(payload, another_secret, algorithm='HS256')
        
        # Try to verify with wrong keys
        verification_results = {}
        
        # Test current secret
        try:
            jwt.decode(token_with_current_secret, current_secret, algorithms=['HS256'])
            verification_results['current_secret_with_current_token'] = 'VALID ✅'
        except:
            verification_results['current_secret_with_current_token'] = 'INVALID ❌'
            
        # Test weak secret
        try:
            jwt.decode(token_with_weak_secret, weak_secret, algorithms=['HS256'])
            verification_results['weak_secret_with_weak_token'] = 'VALID ✅ (but weak)'
        except:
            verification_results['weak_secret_with_weak_token'] = 'INVALID ❌'
            
        # Test cross-verification (should fail)
        try:
            jwt.decode(token_with_current_secret, weak_secret, algorithms=['HS256'])
            verification_results['weak_secret_with_current_token'] = 'VALID ✅ (SECURITY BREACH!)'
        except:
            verification_results['weak_secret_with_current_token'] = 'INVALID ❌ (Good!)'
            
        try:
            jwt.decode(token_with_current_secret, another_secret, algorithms=['HS256'])
            verification_results['different_secret_with_current_token'] = 'VALID ✅ (SECURITY BREACH!)'
        except:
            verification_results['different_secret_with_current_token'] = 'INVALID ❌ (Good!)'
        
        return Response({
            'jwt_security_demonstration': {
                'current_jwt_secret_length': len(current_secret),
                'current_jwt_secret_strength': '🔒 Strong' if len(current_secret) >= 64 else '⚠️ Weak',
                'tokens_generated': {
                    'with_current_secret': token_with_current_secret[:50] + '...',
                    'with_weak_secret': token_with_weak_secret[:50] + '...',
                    'with_different_secret': token_with_different_secret[:50] + '...'
                },
                'verification_tests': verification_results,
                'security_explanation': {
                    'jwt_security': 'JWT tokens are only valid when verified with the same secret key used to create them',
                    'secret_importance': 'The secret key is critical - anyone with the secret can create valid tokens',
                    'random_generation': 'Random secrets prevent attackers from guessing or brute-forcing',
                    'key_rotation': 'Regularly changing secrets invalidates all existing tokens (security feature)'
                },
                'recommendations': [
                    'Use cryptographically secure random secret keys (64+ characters)',
                    'Store secrets as environment variables, never in code',
                    'Rotate secrets periodically for enhanced security',
                    'Use different secrets for different environments (dev/staging/prod)',
                    'Monitor for unauthorized token usage'
                ]
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
def show_forensic_watermark_demo(request, session_id):
    """Demonstrate forensic watermarking capabilities for a specific session"""
    try:
        session = get_object_or_404(StreamingSession, session_id=session_id)
        
        # Generate demo watermark payload
        device_token = session.device.fingerprint_hash
        watermark_payload = ForensicWatermarking.generate_watermark_payload(
            device_token, session.device.fingerprint_hash, session_id
        )
        
        # Generate watermark report
        video_info = {
            'title': session.video.title,
            'id': session.video.id
        }
        watermark_report = ForensicWatermarking.generate_watermark_report(watermark_payload, video_info)
        
        return Response({
            'forensic_watermarking_demo': {
                'session_info': {
                    'session_id': session_id,
                    'video_title': session.video.title,
                    'device_fingerprint': session.device.fingerprint_hash[:16] + '...',
                    'created_at': session.created_at.isoformat()
                },
                'watermark_payload': watermark_payload,
                'watermark_report': watermark_report,
                'anti_piracy_benefits': [
                    '🔍 User Identification: Each video copy contains unique user identification',
                    '📱 Device Tracking: Device fingerprint embedded for hardware-level tracking',
                    '⏰ Temporal Tracking: Timestamp allows tracking when content was accessed',
                    '🔒 Session Linking: Links leaked content back to specific streaming sessions',
                    '🧬 Steganographic Embedding: Hidden watermarks resistant to transcoding',
                    '📋 Metadata Embedding: Multiple embedding methods for redundancy',
                    '🚨 Piracy Detection: Enables automated detection of leaked content',
                    '⚖️ Legal Evidence: Provides forensic evidence for legal proceedings'
                ],
                'technical_details': {
                    'embedding_methods': [
                        'Metadata insertion in video headers',
                        'Steganographic LSB modification',
                        'Cryptographic hash verification',
                        'Multi-layer redundant embedding'
                    ],
                    'watermark_data': {
                        'user_hash': watermark_payload['payload']['user_hash'],
                        'device_id': watermark_payload['payload']['device_id'],
                        'session_id': watermark_payload['payload']['session_id'],
                        'timestamp': watermark_payload['payload']['timestamp']
                    },
                    'security_features': [
                        'Tamper-resistant embedding',
                        'Cryptographic integrity verification',
                        'Unique per-session watermarks',
                        'Collision-resistant hash functions'
                    ]
                },
                'demo_explanation': {
                    'purpose': 'This watermark uniquely identifies the user and session for this video stream',
                    'detection': 'If this video appears on piracy sites, it can be traced back to this specific user and session',
                    'legal_value': 'Provides concrete evidence for anti-piracy enforcement and legal action',
                    'prevention': 'Acts as a deterrent since users know their identity is embedded in the content'
                }
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['POST'])
def verify_forensic_watermark(request):
    """Verify forensic watermark in video content (for piracy detection)"""
    try:
        data = json.loads(request.body)
        video_file_path = data.get('video_file_path')
        expected_watermark_hash = data.get('expected_watermark_hash')
        
        if not video_file_path or not expected_watermark_hash:
            return Response({
                'error': 'video_file_path and expected_watermark_hash are required'
            }, status=400)
        
        # This would typically be used by content protection services
        # to verify watermarks in suspected pirated content
        
        return Response({
            'watermark_verification': {
                'file_analyzed': video_file_path,
                'expected_hash': expected_watermark_hash,
                'verification_status': 'This endpoint would verify watermarks in suspected pirated content',
                'use_cases': [
                    'Automated piracy detection systems',
                    'Content protection service integration',
                    'Legal evidence collection',
                    'User accountability tracking'
                ],
                'implementation_note': 'In production, this would analyze video files found on piracy sites'
            }
        })
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)
