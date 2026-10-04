// server/server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const fileRoutes = require('./routes/fileRoutes');
const Message = require('./models/Message');         
const User = require('./models/User');
const UserActivity = require('./models/UserActivity');
const { encrypt } = require('./utils/cryptoHelper');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication required'));
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    if (!await User.exists({ _id: socket.user.id })) {
      return next(new Error('Account no longer exists'));
    }
    next();
  } catch (err) {
    next(new Error('Invalid socket token'));
  }
});

app.use(cors());
app.use(express.json());

// Register API Routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/files', fileRoutes);

app.delete('/api/auth/account', require('./middleware/auth').verifyToken, async (req, res) => {
  try {
    const userId = String(req.user.id);
    const user = await User.findById(userId).select('name email createdBy publicKey');
    if (!user) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (user.publicKey) {
      await Message.updateMany(
        { sender: userId, senderPublicKey: { $in: [null, ''] } },
        { $set: { senderPublicKey: user.publicKey } }
      );
    }

    await User.findByIdAndDelete(userId);
    await UserActivity.deleteMany({ userId });

    for (const socket of io.sockets.sockets.values()) {
      if (String(socket.user?.id) === userId) {
        socket.disconnect(true);
      }
    }
    onlineUsers.delete(userId);
    io.emit('getOnlineUsers', Array.from(onlineUsers.keys()));

    const notification = {
      deletedUserId: userId,
      deletedUserName: user.name,
      deletedUserEmail: user.email,
      deletedAt: new Date()
    };
    const adminRoom = user.createdBy ? `admin:${user.createdBy}` : 'admin-monitor';
    io.to(adminRoom).emit('accountDeleted', notification);
    if (adminRoom !== 'admin-monitor') {
      io.to('admin-monitor').emit('accountDeleted', notification);
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Account deletion error:', err);
    return res.status(500).json({ error: 'Could not delete this account' });
  }
});

// Safe user message retrieval with automatic status update to 'seen'
app.get('/api/messages/:otherUserId', require('./middleware/auth').verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const otherUserId = req.params.otherUserId;
    const conversationId = [userId, otherUserId].sort().join('_');

    // Mark unread messages sent by the counterpart as seen
    await Message.updateMany(
      { conversationId, sender: otherUserId, receiver: userId, status: { $ne: 'seen' } },
      { $set: { status: 'seen' } }
    );

    const messages = await Message.find({
      conversationId,
      hiddenFor: { $ne: userId }
    }).sort({ createdAt: 1 });
    
    // Server passes complete cryptographic envelope to browser engines
    const historyPayload = messages.map((msg) => ({
      _id: msg._id,
      conversationId: msg.conversationId,
      sender: msg.sender,
      receiver: msg.receiver,
      messageType: msg.messageType || 'text',
      senderPublicKey: msg.senderPublicKey || null,
      fileName: msg.fileData?.fileName || '',
      fileData: msg.fileData,
      encryptedText: msg.encryptedText || '',
      iv: msg.iv || '',
      authTag: msg.authTag || '',
      recipientKeyWrap: msg.recipientKeyWrap || null,
      senderKeyWrap: msg.senderKeyWrap || null,
      adminKeyWrap: msg.adminKeyWrap || null,
      auditPayload: msg.auditPayload || null, // Ensure master vault audit payload is returned
      auditIv: msg.auditIv || null,           // Ensure master vault audit IV is returned
      isDeleted: msg.isDeleted || false,
      text: '',
      status: msg.status || 'sent',
      createdAt: msg.createdAt
    }));

    res.json(historyPayload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/messages/:otherUserId', require('./middleware/auth').verifyToken, async (req, res) => {
  try {
    const userId = String(req.user.id);
    const otherUserId = req.params.otherUserId;
    if (!mongoose.Types.ObjectId.isValid(otherUserId) || otherUserId === userId) {
      return res.status(400).json({ error: 'A valid conversation partner is required' });
    }

    const [clearingUser, otherUser] = await Promise.all([
      User.findById(userId).select('name email createdBy'),
      User.findById(otherUserId).select('name email')
    ]);
    if (!clearingUser || !otherUser) {
      return res.status(404).json({ error: 'Conversation user not found' });
    }

    const conversationId = [userId, String(otherUserId)].sort().join('_');
    const result = await Message.updateMany(
      { conversationId, hiddenFor: { $ne: userId } },
      { $addToSet: { hiddenFor: userId } }
    );

    if (result.modifiedCount > 0) {
      const notification = {
        clearingUserName: clearingUser.name,
        clearingUserEmail: clearingUser.email,
        otherUserName: otherUser.name,
        otherUserEmail: otherUser.email,
        conversationId,
        messageCount: result.modifiedCount,
        clearedAt: new Date()
      };
      const adminRoom = clearingUser.createdBy
        ? `admin:${clearingUser.createdBy}`
        : 'admin-monitor';
      io.to(adminRoom).emit('conversationCleared', notification);
    }

    res.json({ success: true, messageCount: result.modifiedCount });
  } catch (err) {
    console.error('Conversation clear error:', err);
    res.status(500).json({ error: 'Could not clear this conversation' });
  }
});

// Real-time socket session mappings
const onlineUsers = new Map(); // userId -> socketId
const activeSessions = new Map(); // socketId -> { userId, sessionRecordId }

io.on('connection', (socket) => {
  // Join global admin audit room
  socket.on('joinAdminMonitor', () => {
    if (socket.user.role === 'admin') {
      socket.join('admin-monitor');
      socket.join(`admin:${socket.user.id}`);
    }
  });

  // Track user login and online presence
  socket.on('join', async () => {
    try {
      const userId = String(socket.user.id);
      onlineUsers.set(userId, socket.id);

      const activity = await UserActivity.create({
        userId,
        socketId: socket.id,
        loginAt: new Date(),
        status: 'online'
      });

      activeSessions.set(socket.id, { userId, sessionRecordId: activity._id });
      io.emit('getOnlineUsers', Array.from(onlineUsers.keys()));
    } catch (err) {
      console.error('Session initialization error:', err);
    }
  });

  // Handle typing status indicators
  socket.on('typing', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userTyping', { senderId });
    }
  });

  socket.on('stopTyping', ({ senderId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('userStopTyping', { senderId });
    }
  });

  // Message processing: DB persistence, user dispatch, and live admin streaming
  socket.on('sendMessage', async (data, acknowledge) => {
    try {
      const {
        senderId: requestedSenderId,
        receiverId,
        text,
        encryptedText,
        iv,
        authTag,
        isFile,
        fileData,
        msgId,
        recipientKeyWrap,
        senderKeyWrap,
        adminKeyWrap,
        auditPayload, // Extracted from client Chat.jsx
        auditIv       // Extracted from client Chat.jsx
      } = data;

      const senderId = String(socket.user.id);
      if (requestedSenderId && String(requestedSenderId) !== senderId) {
        throw new Error('Sender identity does not match socket identity');
      }
      if (!await User.exists({ _id: receiverId })) {
        throw new Error('Recipient account no longer exists');
      }

      const conversationId = [senderId, receiverId].sort().join('_');
      const receiverSocketId = onlineUsers.get(receiverId);
      const initialStatus = receiverSocketId ? 'delivered' : 'sent';

      let payload;

      if (isFile) {
        const savedFileMsg = await Message.findByIdAndUpdate(
          msgId,
          { status: initialStatus },
          { returnDocument: 'after' } 
        );

        payload = {
          _id: msgId,
          conversationId,
          sender: senderId,
          receiver: receiverId,
          messageType: savedFileMsg?.messageType || fileData?.messageType || 'file',
          fileName: savedFileMsg?.fileData?.fileName || fileData?.fileName,
          fileData: savedFileMsg?.fileData || fileData,
          iv: savedFileMsg?.iv,
          authTag: savedFileMsg?.authTag,
          recipientKeyWrap: savedFileMsg?.recipientKeyWrap,
          senderKeyWrap: savedFileMsg?.senderKeyWrap,
          adminKeyWrap: savedFileMsg?.adminKeyWrap,
          auditPayload: savedFileMsg?.auditPayload || null,
          auditIv: savedFileMsg?.auditIv || null,
          isDeleted: false,
          text: '',
          status: initialStatus,
          createdAt: savedFileMsg?.createdAt || new Date()
        };
      } else {
        let finalEncryptedText = encryptedText;
        let finalIv = iv;
        let finalAuthTag = authTag;

        // Fallback: Perform server-side symmetric encryption only if raw plaintext was sent
        if (!encryptedText && text && typeof text === 'string') {
          const encrypted = encrypt(text);
          finalEncryptedText = encrypted.encryptedText;
          finalIv = encrypted.iv;
          finalAuthTag = encrypted.authTag;
        }

        const savedMsg = await Message.create({
          conversationId,
          sender: senderId,
          receiver: receiverId,
          messageType: 'text',
          encryptedText: finalEncryptedText,
          iv: finalIv || '',
          authTag: finalAuthTag || '',
          recipientKeyWrap: recipientKeyWrap || null,
          senderKeyWrap: senderKeyWrap || null,
          adminKeyWrap: adminKeyWrap || null,
          auditPayload: auditPayload || null, // Persist audit payload to Mongo
          auditIv: auditIv || null,           // Persist audit IV to Mongo
          status: initialStatus,
          isDeleted: false
        });

        payload = {
          _id: savedMsg._id,
          conversationId,
          sender: senderId,
          receiver: receiverId,
          messageType: 'text',
          encryptedText: finalEncryptedText,
          iv: finalIv,
          authTag: finalAuthTag,
          recipientKeyWrap: savedMsg.recipientKeyWrap,
          senderKeyWrap: savedMsg.senderKeyWrap,
          adminKeyWrap: savedMsg.adminKeyWrap,
          auditPayload: savedMsg.auditPayload,
          auditIv: savedMsg.auditIv,
          isDeleted: false,
          text: text || '',
          status: initialStatus,
          createdAt: savedMsg.createdAt
        };
      }

      // Deliver to recipient
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receiveMessage', payload);
      }

      // Echo back to sender
      socket.emit('messageSent', payload);
      acknowledge?.({ ok: true, messageId: payload._id });

      // Stream to live admin monitoring feed with sender's public key
      const senderDoc = await User.findById(senderId).select('publicKey');
      io.to('admin-monitor').emit('liveAdminFeed', {
        ...payload,
        senderPublicKey: senderDoc?.publicKey || null
      });

    } catch (err) {
      console.error('Socket sendMessage error:', err);
      acknowledge?.({ ok: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // DELETE MESSAGE EVENT (For Everyone)
  // -------------------------------------------------------------
  socket.on('deleteMessage', async ({ msgId, receiverId }) => {
    try {
      const senderId = String(socket.user.id);
      
      const msg = await Message.findOne({ _id: msgId, sender: senderId });
      if (!msg) return;

      // Secure E2EE Deletion: Erase keys and payload from database completely
      msg.isDeleted = true;
      msg.encryptedText = '';
      msg.iv = '';
      msg.authTag = '';
      msg.recipientKeyWrap = null;
      msg.senderKeyWrap = null;
      msg.adminKeyWrap = null;
      msg.auditPayload = null;
      msg.auditIv = null;
      msg.fileData = null;
      msg.messageType = 'text';
      await msg.save();

      socket.emit('messageDeleted', { msgId });
      
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('messageDeleted', { msgId });
      }

      io.to('admin-monitor').emit('messageDeleted', { msgId, conversationId: msg.conversationId });
    } catch (err) {
      console.error('Delete message error:', err);
    }
  });

  // Handle read receipts
  socket.on('markAsSeen', async ({ senderId }) => {
    const viewerId = String(socket.user.id);
    const conversationId = [senderId, viewerId].sort().join('_');

    await Message.updateMany(
      { conversationId, sender: senderId, receiver: viewerId, status: { $ne: 'seen' } },
      { $set: { status: 'seen' } }
    );

    const senderSocketId = onlineUsers.get(senderId);
    if (senderSocketId) {
      io.to(senderSocketId).emit('messagesSeen', { conversationId });
    }
  });

  // Handle disconnection and duration calculation
  socket.on('disconnect', async () => {
    try {
      const session = activeSessions.get(socket.id);
      if (session) {
        const logoutTime = new Date();
        const activity = await UserActivity.findById(session.sessionRecordId);

        if (activity) {
          const duration = Math.round((logoutTime.getTime() - new Date(activity.loginAt).getTime()) / 1000);
          activity.logoutAt = logoutTime;
          activity.durationSeconds = duration;
          activity.status = 'offline';
          await activity.save();
        }

        onlineUsers.delete(session.userId);
        activeSessions.delete(socket.id);
        io.emit('getOnlineUsers', Array.from(onlineUsers.keys()));
      }
    } catch (err) {
      console.error('Logout logging error:', err);
    }
  });
});

// Database connection setup
const PORT = process.env.PORT || 5000;

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Stop the existing server before starting another one.`);
    process.exitCode = 1;
    return;
  }

  console.error('Server listener error:', err);
  process.exitCode = 1;
});

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => {
    console.log('MongoDB Connected successfully');
    server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error('MongoDB Connection Error:', err));