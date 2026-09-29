// server/routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const Message = require('../models/Message');
const UserActivity = require('../models/UserActivity');
const User = require('../models/User');
const { verifyAdmin } = require('../middleware/auth');
const { decrypt } = require('../utils/cryptoHelper');

// 1. Fetch conversations with populated user names
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

    // Resolve user IDs to display actual user credentials
    const conversations = await Promise.all(
      rawConversations.map(async (conv) => {
        if (!conv._id) return null; // Safety check to prevent crash

        const [user1Id, user2Id] = conv._id.split('_');
        const [user1, user2] = await Promise.all([
          User.findById(user1Id).select('name email role'),
          User.findById(user2Id).select('name email role')
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

    // Remove any null values from safety check
    res.json(conversations.filter(Boolean));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Paginated conversation retrieval with batch decryption
router.get('/conversation/:conversationId', verifyAdmin, async (req, res) => {
  try {
    const { before, limit = 40 } = req.query;
    const query = { conversationId: req.params.conversationId };

    // Cursor filter for older message pagination
    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    // Limit retrieval batch to prevent memory overload
    const messages = await Message.find(query)
      .populate('sender', 'name email publicKey')
      .populate('receiver', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    // Order chronologically for the UI
    const chronologicalMessages = messages.reverse();

    const decryptedMessages = chronologicalMessages.map((msg) => {
      let plaintext = '';
      if (msg.messageType === 'text' && !msg.adminKeyWrap) {
        try {
          plaintext = decrypt(msg.encryptedText, msg.iv, msg.authTag);
        } catch (e) {
          plaintext = '[Decryption Failed]';
        }
      }

      return {
        _id: msg._id,
        sender: msg.sender,
        receiver: msg.receiver,
        messageType: msg.messageType,
        fileName: msg.fileData?.fileName || '',
        encryptedText: msg.encryptedText,
        iv: msg.iv,
        authTag: msg.authTag,
        adminKeyWrap: msg.adminKeyWrap,
        senderPublicKey: msg.sender?.publicKey || null,
        text: plaintext,
        createdAt: msg.createdAt
      };
    });

    res.json({
      messages: decryptedMessages,
      hasMore: messages.length === parseInt(limit),
      nextCursor: messages.length > 0 ? messages[0].createdAt : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Retrieve user activity and duration logs (SMART SPAM FILTER ADDED)
router.get('/activity-logs', verifyAdmin, async (req, res) => {
  try {
    // Increased limit to 300 to ensure no user gets hidden
    const logs = await UserActivity.find()
      .populate('userId', 'name email role')
      .sort({ loginAt: -1 })
      .limit(300);

    // Filter out developer hot-reload spam (sessions that lasted less than 3 seconds)
    const cleanedLogs = logs.filter(log => {
      if (!log.logoutAt) return true; // Keep currently online users
      const durationMs = new Date(log.logoutAt) - new Date(log.loginAt);
      return durationMs > 3000; // Keep only if session lasted longer than 3 seconds
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

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'user'
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