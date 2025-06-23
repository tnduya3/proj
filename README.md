# Secure Video Streaming System (Netflix-like)

This project simulates a secure video streaming system similar to Netflix, implementing advanced security measures including Diffie-Hellman key exchange, AES encryption, and device fingerprinting with **real-time cryptographic protection demonstrations**.

## 🔒 Security Features

### Client-Side Security
- **Device Fingerprinting**: Generates unique device identifiers based on browser characteristics
- **JWT Authentication**: Time-limited tokens (5 minutes expiration)
- **Diffie-Hellman Key Exchange**: Secure key negotiation between client and server
- **Content Decryption**: Client-side "Black Box" for video decryption
- **AES-256-GCM Encryption**: Industry-standard video content encryption
- **Real-time Security Monitoring**: Live demonstration of encryption processes

### Server-Side Security
- **PostgreSQL Database**: Secure storage of device fingerprints and session data
- **Dynamic CEK Generation**: Unique Content Encryption Key for each streaming session
- **Session Management**: Time-based session expiration with automatic cleanup
- **DASH Streaming**: Dynamic Adaptive Streaming over HTTP
- **Encrypted Video Storage**: Videos encrypted at rest with session-specific keys
- **Multi-layer Protection**: File-level + transport-level + session-level encryption

### Anti-Piracy Protection
- **Direct File Access Blocking**: Video files cannot be accessed via direct URLs
- **Session-Based Access Control**: Content only accessible through valid encrypted sessions
- **Dynamic Key Rotation**: New encryption keys generated for every streaming session
- **Device Binding**: Encryption keys tied to specific device fingerprints
- **Time-Limited Access**: Automatic session expiration prevents persistent access
- **No Persistent Keys**: Client never stores long-term decryption keys

## 🏗️ System Architecture

```
[Client Browser] <---> [Django Server] <---> [PostgreSQL Database]
       |                      |                       |
   Fingerprint            Key Management         Device Data
   JWT Token              Video Processing       Session Data
   DH Exchange            DASH Streaming         Video Metadata
   Video Decryption       CEK Generation
   Security Demos         Anti-Piracy Enforcement
```

## 🚀 Setup Instructions

### Prerequisites
- Python 3.13
- PostgreSQL
- FFmpeg (for video processing)

### Installation

1. **Activate Virtual Environment**
   ```bash
   venv_313\Scripts\activate
   ```

2. **Install Dependencies**
   ```bash
   pip install django djangorestframework cryptography psycopg2-binary PyJWT
   ```

3. **Database Setup**
   - Ensure PostgreSQL is running
   - Database configuration is in `settings.py`

4. **Run Migrations**
   ```bash
   python manage.py migrate
   ```

5. **Create Sample Data**
   ```bash
   python manage.py create_sample_data
   ```

6. **Start Server**
   ```bash
   python manage.py runserver 8000
   ```

## 🎥 Usage & Demonstrations

### Basic Usage
1. **Access the Application**: Open browser and go to `http://localhost:8000`
2. **Select a video** from the available list
3. **Start Secure Streaming**: Click the button to begin the security flow

### 🔐 Cryptographic Demonstrations

#### **🔒 Encryption Demo**
- Click **"Show Encryption Demo"** to see:
  - Raw video data (readable patterns)
  - Same data after AES-256-GCM encryption (completely randomized)
  - The actual Content Encryption Key (CEK) used
  - Proof that encrypted data is cryptographically secure

#### **📊 Session Security Analysis**
- Click **"Show Session Security"** (after starting streaming) to view:
  - Diffie-Hellman key exchange details
  - Encrypted CEK (unique per session)
  - Time-based security measures
  - Device fingerprint validation
  - Complete anti-piracy measures

#### **🛡️ Anti-Piracy Protection Demo**
- Click **"Anti-Piracy Demo"** to see:
  - Direct file access blocking
  - Multi-layer encryption protection
  - Dynamic security measures
  - Session-based access requirements

### Security Flow Demonstration
```
1. Device Registration → JWT Token (5-min expiry)
2. Stream Request → DH Public Key Exchange
3. Key Exchange Completion → Encrypted CEK Generation
4. Video Manifest → DASH Streaming URLs
5. Encrypted Streaming → Client-side Decryption
6. Real-time Monitoring → Security Analysis Display
```

## 🔧 Technical Implementation

### Key Components

1. **Models** (`models.py`)
   - `Device`: Device fingerprinting and authentication
   - `Video`: Video metadata and file paths
   - `StreamingSession`: Session management and encryption keys

2. **Cryptographic Utils** (`crypto_utils.py`)
   - `DiffieHellmanKeyExchange`: Secure key negotiation
   - `ContentEncryption`: AES-256-GCM encryption/decryption
   - `DeviceFingerprinting`: JWT token management
   - `VideoProcessor`: Video encryption and DASH processing

3. **API Views** (`views.py`)
   - Device registration and authentication
   - Video streaming request handling
   - Key exchange endpoints
   - DASH manifest generation
   - Encrypted video streaming
   - **NEW**: Cryptographic demonstration endpoints

4. **Client-Side Security** (`player.html`)
   - Device fingerprint generation
   - Secure key exchange implementation
   - Content decryption "Black Box"
   - Video player integration
   - **NEW**: Real-time security monitoring interface

### 🆕 New Demo Endpoints

- `GET /api/demo/encryption/<video_id>/` - Shows encryption demonstration
- `GET /api/demo/security/<session_id>/` - Displays session security analysis
- `GET /api/demo/protection/` - Demonstrates anti-piracy measures
- `GET /api/test/video/<video_id>/` - Tests video file availability

### Security Measures Against Piracy

1. **Multi-Layer Encryption**:
   - File-level: Videos encrypted with unique CEK per session
   - Transport-level: DH session key encryption
   - Device-level: Device-specific key derivation

2. **Dynamic Security**:
   - New encryption keys for every streaming session
   - Time-limited access (5-minute sessions)
   - Device fingerprint validation

3. **Access Control**:
   - No direct file access via URLs
   - Session-based streaming only
   - Encrypted content at rest

4. **Real-time Protection**:
   - Session expiration monitoring
   - Invalid access attempt detection
   - Automatic key rotation

## 📁 Project Structure

```
project/
├── video_app/
│   ├── models.py              # Database models
│   ├── views.py               # API endpoints and demo functions
│   ├── crypto_utils.py        # Cryptographic utilities
│   ├── urls.py                # URL routing
│   ├── example.mp4            # Sample video file
│   └── management/
│       └── commands/
│           ├── create_sample_data.py
│           └── encrypt_videos.py    # NEW: Video encryption utility
├── templates/
│   └── video_app/
│       └── player.html        # Enhanced client interface with demos
├── static/                    # Static files
├── project/
│   ├── settings.py            # Django configuration
│   └── urls.py                # Main URL routing
└── manage.py                  # Django management script
```

## 🔍 Testing the Cryptographic Protection

### 1. Encryption Verification
```bash
# Test encryption demonstration
curl http://localhost:8000/api/demo/encryption/1/
```

### 2. Session Security Analysis
```bash
# Start a streaming session first, then:
curl http://localhost:8000/api/demo/security/{session_id}/
```

### 3. Anti-Piracy Protection Test
```bash
# View protection measures
curl http://localhost:8000/api/demo/protection/
```

### 4. Direct Access Blocking Test
```bash
# Try to access video directly (should fail)
curl http://localhost:8000/media/video_app/example.mp4
# Result: 404 or access denied
```

## 🛡️ Security Validation

### Current Implementation ✅
- ✅ Device fingerprinting with SHA-256 hashing
- ✅ JWT authentication with 5-minute expiration
- ✅ Simplified Diffie-Hellman key exchange
- ✅ AES-256-GCM content encryption
- ✅ Session-based access control
- ✅ Client-side decryption implementation
- ✅ **Real-time encryption demonstrations**
- ✅ **Session security monitoring**
- ✅ **Anti-piracy protection visualization**

### Production Enhancements 🔄
- 🔄 Hardware-based DRM integration
- 🔄 Advanced obfuscation techniques
- 🔄 Real-time piracy detection algorithms
- 🔄 Watermarking implementation
- 🔄 CDN integration for global scalability
- 🔄 Advanced DASH segmentation

## 📚 Educational Demonstrations

This system demonstrates:
- **Modern Cryptographic Techniques**: Real AES-256-GCM encryption in action
- **Key Management**: Secure key generation, exchange, and rotation
- **Session Security**: Time-based access control and device binding
- **Content Protection**: Multi-layer encryption and access control
- **Anti-Piracy Measures**: Comprehensive protection against unauthorized copying
- **Real-world Applications**: How streaming platforms protect content

## 🎯 Key Learning Outcomes

1. **Cryptographic Protection**: Understanding how encryption protects digital content
2. **Key Exchange Protocols**: Implementation of Diffie-Hellman key agreement
3. **Session Management**: Time-based security and access control
4. **Device Authentication**: Fingerprinting and device-specific security
5. **Content Delivery**: Secure streaming with real-time protection monitoring

## ⚠️ Disclaimer

This is an educational implementation demonstrating cryptographic concepts in video streaming. Production systems require additional security measures, compliance with DRM standards, hardware security modules, and extensive security auditing.
