// server/routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const Message = require('../models/Message');
const UserActivity = require('../models/UserActivity');
const User = require('../models/User');
const { verifyAdmin } = require('../middleware/auth');
const { decrypt } = require('../utils/cryptoHelper');

// 1. Fetch conversations with populated user names & public keys
router.get('/conversations', verifyAdmin, async (req, res) => {
  try {
    const rawConversations = await Message.aggregate([
      {
        $group: {
          _id: '$conversationId',
          lastMessageAt: { $max: '$createdAt' },
          totalMessages: { $sum: 1 }
        }
      },
      { $sort: { lastMessageAt: -1 } }
    ]);

    // Resolve user IDs to display actual user credentials including public keys
    const conversations = await Promise.all(
      rawConversations.map(async (conv) => {
        if (!conv._id) return null;

        const [user1Id, user2Id] = conv._id.split('_');
        const [user1, user2] = await Promise.all([
          User.findById(user1Id).select('name email role publicKey'),
          User.findById(user2Id).select('name email role publicKey')
        ]);

        return {
          _id: conv._id,
          user1: user1 || { name: 'Unknown User' },
          user2: user2 || { name: 'Unknown User' },
          lastMessageAt: conv.lastMessageAt,
          totalMessages: conv.totalMessages
        };
      })
    );

    res.json(conversations.filter(Boolean));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Paginated conversation retrieval
router.get('/conversation/:conversationId', verifyAdmin, async (req, res) => {
  try {
    const { before, limit = 50 } = req.query;
    const query = { conversationId: req.params.conversationId };

    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    const messages = await Message.find(query)
      .populate('sender', 'name email publicKey')
      .populate('receiver', 'name email publicKey')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    // Chronological order for frontend UI
    const chronologicalMessages = messages.reverse();

    const formattedMessages = chronologicalMessages.map((msg) => {
      let plaintext = '';

      // Agar server-side legacy static tunnel decrypt possible ho
      if (msg.messageType === 'text' && !msg.adminKeyWrap && msg.encryptedText) {
        try {
          plaintext = decrypt(msg.encryptedText, msg.iv, msg.authTag) || '';
        } catch (e) {
          plaintext = ''; // Error string na bhejein taaki client-side engine decrypt kare
        }
      }

      return {
        _id: msg._id,
        conversationId: msg.conversationId,
        sender: msg.sender,
        receiver: msg.receiver,
        messageType: msg.messageType,
        fileName: msg.fileData?.fileName || msg.fileName || '',
        fileData: msg.fileData || null,
        encryptedText: msg.encryptedText,
        iv: msg.iv,
        authTag: msg.authTag,
        adminKeyWrap: msg.adminKeyWrap || null,
        senderKeyWrap: msg.senderKeyWrap || null,
        recipientKeyWrap: msg.recipientKeyWrap || null,
        auditPayload: msg.auditPayload || null,
        auditIv: msg.auditIv || null,
        senderPublicKey: msg.sender?.publicKey || null,
        text: plaintext, // Agar empty hoga toh AdminDashboard ka WebCrypto decrypt karega
        isDeleted: msg.isDeleted || false,
        createdAt: msg.createdAt
      };
    });

    res.json({
      messages: formattedMessages,
      hasMore: messages.length === parseInt(limit),
      nextCursor: messages.length > 0 ? messages[0].createdAt : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Retrieve user activity and duration logs
router.get('/activity-logs', verifyAdmin, async (req, res) => {
  try {
    const logs = await UserActivity.find()
      .populate('userId', 'name email role')
      .sort({ loginAt: -1 })
      .limit(300);

    const cleanedLogs = logs.filter((log) => {
      if (!log.logoutAt) return true;
      const durationMs = new Date(log.logoutAt) - new Date(log.loginAt);
      return durationMs > 3000;
    });

    res.json(cleanedLogs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Admin creates a new user account
router.post('/create-user', verifyAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'user',
      createdBy: req.user.id
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;