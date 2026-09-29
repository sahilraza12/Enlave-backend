// server/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { verifyToken } = require('../middleware/auth');

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, role, publicKey } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'user',
      publicKey: publicKey || null
    });

    res.status(201).json({ message: 'User registered successfully', userId: user._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        publicKey: user.publicKey || null
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update User's ECDH Public Key
router.put('/public-key', verifyToken, async (req, res) => {
  try {
    const { publicKey } = req.body;
    if (!publicKey) {
      return res.status(400).json({ message: 'publicKey is required' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { publicKey },
      { new: true }
    ).select('-password');

    res.json({ message: 'Public key updated successfully', user: updatedUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// MULTI-DEVICE KEY SYNC ENDPOINTS (Phone & Cross-Device Support)
// -------------------------------------------------------------

// 1. Save Keys Backup to Cloud (Called by Laptop after key creation)
router.post('/sync-keys', verifyToken, async (req, res) => {
  try {
    const { publicKey, privateKey } = req.body;
    if (!privateKey) {
      return res.status(400).json({ message: 'privateKey is required for sync' });
    }

    await User.findByIdAndUpdate(req.user.id, {
      publicKey,
      privateKey
    });

    res.json({ success: true, message: 'Keys securely synced to user vault' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Restore Keys on New Device (Called by Phone to fetch original keys)
router.get('/my-keys', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('publicKey privateKey');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      publicKey: user.publicKey || null,
      privateKey: user.privateKey || null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fetch Active Admin's Public Key (For Envelope Encryption / Escrow)
router.get('/admin-public-key', verifyToken, async (req, res) => {
  try {
    const admin = await User.findOne({ role: 'admin' }).select('publicKey name email');
    if (!admin || !admin.publicKey) {
      return res.status(404).json({ message: 'Active admin public key not available' });
    }
    res.json(admin);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all users (except current logged in user) with their public keys
router.get('/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } })
      .select('-password -privateKey'); // Private key kisa doosre ko kabhi leak na ho
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;