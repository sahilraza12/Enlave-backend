// server/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied: No Token' });

  let verified;
  try {
    verified = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(400).json({ message: 'Invalid Token' });
  }

  try {
    const userExists = await User.exists({ _id: verified.id });
    if (!userExists) {
      return res.status(401).json({ message: 'Account no longer exists' });
    }

    req.user = verified;
    return next();
  } catch (err) {
    return next(err);
  }
};

const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ message: 'Access Denied: Admin only' });
    }
  });
};

module.exports = { verifyToken, verifyAdmin };