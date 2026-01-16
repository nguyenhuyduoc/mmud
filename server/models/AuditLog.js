const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
    enum: [
      // Legacy actions (from old code)
      'register', 'login', 'logout',
      'create_secret', 'view_secret', 'edit_secret', 'share_secret', 'delete_secret',
      'access_denied',
      // New actions (from security upgrades)
      'create', 'view', 'edit', 'share', 'delete',
      'key_rotation', 'cert_issue', 'cert_revoke',
      // Integrity & Security
      'tampering_detected', 'checksum_auto_fix'
    ]
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  secret_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Secret'
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  ip_address: String,
  user_agent: String,

  // Basic metadata (unencrypted, for filtering)
  metadata: {
    type: Object,
    default: {}
  },

  // Encrypted sensitive details
  encrypted_details: {
    iv: String,
    ciphertext: String, // Encrypted JSON of sensitive data
    key_id: String // Identifier for which key can decrypt this
  },

  // Searchable hash for encrypted data
  search_hash: String // HMAC of searchable fields for querying
});

// Indexes for performance
AuditLogSchema.index({ user_id: 1, timestamp: -1 });
AuditLogSchema.index({ secret_id: 1, timestamp: -1 });
AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ search_hash: 1 });

// Method to encrypt sensitive details
AuditLogSchema.methods.encryptDetails = async function (encryptionKey, details) {
  const { encryptWithGCM, genRandomSalt, bufferToHex } = require('crypto');
  const { subtle } = require('node:crypto').webcrypto;

  // Import AES key
  const aesKey = await subtle.importKey(
    'raw',
    Buffer.from(encryptionKey, 'hex'),
    'AES-GCM',
    false,
    ['encrypt']
  );

  const iv = genRandomSalt(12);
  const plaintext = JSON.stringify(details);

  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    Buffer.from(plaintext)
  );

  this.encrypted_details = {
    iv: bufferToHex(iv),
    ciphertext: bufferToHex(ciphertext),
    key_id: 'audit-key-v1' // Version identifier
  };
};

// Method to decrypt sensitive details
AuditLogSchema.methods.decryptDetails = async function (encryptionKey) {
  if (!this.encrypted_details || !this.encrypted_details.ciphertext) {
    return null;
  }

  const { subtle } = require('node:crypto').webcrypto;
  const { hexToBuffer, bufferToString } = require('../utils/cryptoHelpers');

  const aesKey = await subtle.importKey(
    'raw',
    Buffer.from(encryptionKey, 'hex'),
    'AES-GCM',
    false,
    ['decrypt']
  );

  const iv = hexToBuffer(this.encrypted_details.iv);
  const ciphertext = hexToBuffer(this.encrypted_details.ciphertext);

  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );

  return JSON.parse(bufferToString(plaintext));
};

// Static method to create searchable hash
AuditLogSchema.statics.createSearchHash = async function (searchableFields) {
  const { subtle } = require('node:crypto').webcrypto;
  const crypto = require('crypto');

  // Create deterministic hash for searching
  const data = JSON.stringify(searchableFields);
  const hash = crypto.createHash('sha256').update(data).digest('hex');

  return hash;
};

module.exports = mongoose.model('AuditLog', AuditLogSchema);
