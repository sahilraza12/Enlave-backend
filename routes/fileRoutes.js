// server/routes/fileRoutes.js
const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const Message = require('../models/Message');
const User = require('../models/User');
const { verifyToken } = require('../middleware/auth');
const { encryptBuffer, decryptBuffer } = require('../utils/cryptoHelper');

// File upload memory storage (files/images ke liye)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB limit
});

// Encrypted files aur voice notes store karne ke liye folder path
const UPLOAD_DIR = path.join(__dirname, '../encrypted_uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// -------------------------------------------------------------
// 1. Regular File / Image Upload (Server-Side Encryption)
// -------------------------------------------------------------
router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    const { receiverId } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    if (!receiverId) {
      return res.status(400).json({ error: 'Receiver ID is required' });
    }
    if (!await User.exists({ _id: receiverId })) {
      return res.status(404).json({ error: 'Recipient account no longer exists' });
    }

    const conversationId = [req.user.id, receiverId].sort().join('_');

    // File buffer ko AES-256-GCM se encrypt karo
    const { encryptedData, iv, authTag } = encryptBuffer(file.buffer);

    // Encrypted file ko unique name ke sath disk par save karo
    const uniqueFileName = `${Date.now()}_enc_${file.originalname}`;
    const encryptedFilePath = path.join(UPLOAD_DIR, uniqueFileName);
    fs.writeFileSync(encryptedFilePath, encryptedData);

    const isImage = file.mimetype.startsWith('image/');

    const newMsg = await Message.create({
      conversationId,
      sender: req.user.id,
      receiver: receiverId,
      messageType: isImage ? 'image' : 'file',
      fileData: {
        fileName: file.originalname,
        mimeType: file.mimetype,
        filePath: uniqueFileName
      },
      iv,
      authTag,
      status: 'sent'
    });

    res.status(201).json({
      success: true,
      message: {
        _id: newMsg._id,
        conversationId,
        sender: req.user.id,
        receiver: receiverId,
        messageType: newMsg.messageType,
        fileName: file.originalname,
        createdAt: newMsg.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. Client-Side E2EE Voice Message Upload (Dual-Envelope)
// -------------------------------------------------------------
router.post('/upload-audio', verifyToken, upload.single('audio'), async (req, res) => {
  try {
    const { receiverId, iv, authTag, recipientKeyWrap, adminKeyWrap } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'No audio recording file provided' });
    }

    if (!receiverId) {
      return res.status(400).json({ error: 'Receiver ID is required' });
    }
    if (!await User.exists({ _id: receiverId })) {
      return res.status(404).json({ error: 'Recipient account no longer exists' });
    }

    const senderId = req.user.id;
    const conversationId = [senderId, receiverId].sort().join('_');

    // Client pehle hi audio ko encrypt karke bhejta hai, toh raw ciphertext save hoga
    const uniqueFileName = `${Date.now()}_voice_${Math.round(Math.random() * 1e9)}.enc`;
    const encryptedFilePath = path.join(UPLOAD_DIR, uniqueFileName);
    fs.writeFileSync(encryptedFilePath, file.buffer);

    const newMsg = await Message.create({
      conversationId,
      sender: senderId,
      receiver: receiverId,
      messageType: 'file', // client isse audio handler se treat karega
      fileData: {
        fileName: file.originalname || 'voicenote.enc',
        mimeType: 'audio/webm',
        filePath: uniqueFileName
      },
      iv: iv || '',
      authTag: authTag || '',
      recipientKeyWrap: recipientKeyWrap || null,
      senderKeyWrap: recipientKeyWrap || null,
      adminKeyWrap: adminKeyWrap || null,
      status: 'sent'
    });

    res.status(201).json({
      success: true,
      message: {
        _id: newMsg._id,
        conversationId,
        sender: senderId,
        receiver: receiverId,
        messageType: 'file',
        fileData: newMsg.fileData,
        iv: newMsg.iv,
        authTag: newMsg.authTag,
        recipientKeyWrap: newMsg.recipientKeyWrap,
        adminKeyWrap: newMsg.adminKeyWrap,
        createdAt: newMsg.createdAt
      }
    });
  } catch (err) {
    console.error('Audio upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. Raw Encrypted Audio Stream (Client / Admin Decrypts via Session Key)
// -------------------------------------------------------------
router.get('/audio/:messageId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;

    if (!token) {
      return res.status(401).json({ error: 'Access Denied: No Token Provided' });
    }

    let decodedUser;
    try {
      decodedUser = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or Expired Token' });
    }

    if (!await User.exists({ _id: decodedUser.id })) {
      return res.status(401).json({ error: 'Account no longer exists' });
    }

    const msg = await Message.findById(req.params.messageId);
    if (!msg || !msg.fileData?.filePath) {
      return res.status(404).json({ error: 'Voice recording not found' });
    }

    // Role Access: Sirf Sender, Receiver ya Admin hi download/stream kar sakte hain
    const isAuthorized =
      decodedUser.role === 'admin' ||
      msg.sender.toString() === decodedUser.id ||
      msg.receiver.toString() === decodedUser.id;

    if (!isAuthorized) {
      return res.status(403).json({ error: 'Unauthorized to access this audio note' });
    }

    const fullPath = path.join(UPLOAD_DIR, msg.fileData.filePath);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'Encrypted audio not found on disk' });
    }

    // Return the raw encrypted octet-stream directly
    res.setHeader('Content-Type', 'application/octet-stream');
    res.sendFile(fullPath);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 4. Regular File / Image Decrypted Download
// -------------------------------------------------------------
router.get('/download/:messageId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;

    if (!token) {
      return res.status(401).json({ error: 'Access Denied: No Token Provided' });
    }

    let decodedUser;
    try {
      decodedUser = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or Expired Token' });
    }

    if (!await User.exists({ _id: decodedUser.id })) {
      return res.status(401).json({ error: 'Account no longer exists' });
    }

    const msg = await Message.findById(req.params.messageId);
    if (!msg || !msg.fileData?.filePath) {
      return res.status(404).json({ error: 'File record not found' });
    }

    // Role check: Sender, Receiver ya Admin hi access kar sakte hain
    const isAuthorized =
      decodedUser.role === 'admin' ||
      msg.sender.toString() === decodedUser.id ||
      msg.receiver.toString() === decodedUser.id;

    if (!isAuthorized) {
      return res.status(403).json({ error: 'Access denied to this file' });
    }

    const fullPath = path.join(UPLOAD_DIR, msg.fileData.filePath);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'Encrypted file not found on disk' });
    }

    // Read ciphertext buffer from disk & decrypt
    const encryptedBuffer = fs.readFileSync(fullPath);
    const decryptedBuffer = decryptBuffer(encryptedBuffer, msg.iv, msg.authTag);

    res.setHeader('Content-Type', msg.fileData.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${msg.fileData.fileName}"`);
    res.send(decryptedBuffer);
  } catch (err) {
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
});

module.exports = router;