// server/models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  conversationId: { 
    type: String, 
    required: true, 
    index: true 
  },
  sender: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  receiver: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  messageType: { 
    type: String, 
    enum: ['text', 'file', 'image', 'audio'], 
    default: 'text' 
  },
  encryptedText: { 
    type: String, 
    default: '' 
  },
  
  // Dual-Key Escrow Wraps (Option A)
  recipientKeyWrap: { 
    type: String, 
    default: null 
  },
  senderKeyWrap: { 
    type: String, 
    default: null 
  },
  adminKeyWrap: { 
    type: String, 
    default: null 
  },

  // UNIVERSAL MASTER AUDIT VAULT FIELDS (For phone & cross-device admin decrypt)
  auditPayload: { 
    type: String, 
    default: null 
  },
  auditIv: { 
    type: String, 
    default: null 
  },
  
  fileData: {
    fileName: { type: String, default: '' },
    mimeType: { type: String, default: '' },
    filePath: { type: String, default: '' }
  },
  iv: { 
    type: String, 
    default: '' 
  },
  authTag: { 
    type: String, 
    default: '' 
  },
  status: {
    type: String,
    enum: ['sent', 'delivered', 'seen'],
    default: 'sent'
  },
  
  // Message deletion tracking
  isDeleted: { 
    type: Boolean, 
    default: false 
  }

}, { timestamps: true });

// Compound index for cursor pagination and sorting
messageSchema.index({ conversationId: 1, createdAt: 1 });

module.exports = mongoose.model('Message', messageSchema);