# 🚀 Quick Start Guide - Secure Video Streaming System

## ⚡ Fast Setup (5 Minutes)

### 1. **Start the System**
```bash
cd "proj"
"/proj/venv_313/Scripts/python.exe" manage.py runserver
```

### 2. **Access the Application**
Open browser: `http://localhost:8000`

### 3. **Try the Features**

#### 🎬 **Basic Streaming**
1. **Select a video** from the list
2. **Click "Start Secure Streaming"**
3. **Watch** the security process in action
4. **Video plays** after security setup

#### 🔒 **Cryptographic Demonstrations**

**Show Encryption Demo:**
- Click "🔒 Show Encryption Demo"
- See raw video data vs encrypted data
- Understand AES-256-GCM protection

**Session Security Analysis:**
- Start streaming first
- Click "📊 Show Session Security" 
- View complete security details

**Anti-Piracy Protection:**
- Click "🛡️ Anti-Piracy Demo"
- See all protection measures
- Understand why copying is prevented

---

## 🎯 **What You'll See**

### **Security Flow in Action**
```
Device Registration → Key Exchange → Encryption → Streaming
```

### **Real-time Demonstrations**
- ✅ Raw vs encrypted video data
- ✅ Session security details
- ✅ Anti-piracy measures
- ✅ Live encryption process

### **Protection Against Copying**
- 🚫 Direct file access blocked
- 🔐 Dynamic encryption per session
- ⏰ Time-limited access
- 🖥️ Device-specific keys

---

## 🔧 **API Quick Tests**

### Test Encryption Demo:
```bash
curl http://localhost:8000/api/demo/encryption/1/
```

### Test Anti-Piracy Protection:
```bash
curl http://localhost:8000/api/demo/protection/
```

### Test Direct Access Blocking:
```bash
curl http://localhost:8000/media/video_app/example.mp4
# Should return 404 or access denied
```

---

## 📋 **Key Features Checklist**

- ✅ **Device fingerprinting** working
- ✅ **JWT authentication** with 5-min expiry
- ✅ **Diffie-Hellman key exchange** completed
- ✅ **AES-256-GCM encryption** active
- ✅ **Session management** functional
- ✅ **Video streaming** operational
- ✅ **Real-time demos** available
- ✅ **Anti-piracy protection** active

---

## 🛡️ **Security Verification**

1. **Check encryption demo** - proves cryptographic protection
2. **View session security** - shows key management
3. **Test anti-piracy demo** - demonstrates protection layers
4. **Try direct file access** - confirms access blocking

---

## 📞 **Quick Troubleshooting**

**Server not starting?**
- Check PostgreSQL is running
- Verify Python environment is activated

**Video not playing?**
- Select a video first
- Complete the security flow
- Check debug logs in browser

**Demos not working?**
- Ensure server is running
- Check browser console for errors
- Try refreshing the page

---

## 🎓 **Educational Goals Achieved**

✅ **Cryptographic Protection**: AES-256-GCM in action  
✅ **Key Exchange**: Diffie-Hellman implementation  
✅ **Session Security**: Time-based access control  
✅ **Anti-Piracy**: Comprehensive copy protection  
✅ **Real-time Monitoring**: Live security demonstrations  

---

**Your secure video streaming system is ready! 🎉**

Start with the basic streaming, then explore the cryptographic demonstrations to see how the system protects against video piracy.
