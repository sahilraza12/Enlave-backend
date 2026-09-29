// server/models/UserActivity.js
const mongoose = require('mongoose');

const userActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  socketId: { type: String, required: true },
  loginAt: { type: Date, default: Date.now },
  logoutAt: { type: Date },
  durationSeconds: { type: Number, default: 0 },
  status: { type: String, enum: ['online', 'offline'], default: 'online' }
}, { timestamps: true });

module.exports = mongoose.model('UserActivity', userActivitySchema);