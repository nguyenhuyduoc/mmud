const mongoose = require('mongoose');

const SecretSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Tên gợi nhớ (VD: "DB Production")
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Người tạo
  category: { type: String, default: 'general', enum: ['general', 'cloud', 'database', 'payment', 'api', 'other'] },
  tags: [{ type: String }],

  // Nội dung bí mật đã mã hóa (AES-GCM)
  encrypted_data: {
    iv: { type: String, required: true },
    ciphertext: { type: String, required: true }
  },

  // Danh sách quyền truy cập (Key Wrapping) với RBAC
  access_list: [{
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: {
      type: String,
      enum: ['owner', 'editor', 'sharer', 'viewer'],
      default: 'viewer'
    },
    permissions: {
      can_read: { type: Boolean, default: true },
      can_edit: { type: Boolean, default: false },
      can_share: { type: Boolean, default: false },
      can_delete: { type: Boolean, default: false }
    },
    // Khóa giải mã (Wrapped Key) dành riêng cho user này
    wrapped_key: {
      ephemeral_pub: { type: Object, required: true }, // Khóa tạm ECDH
      iv: { type: String, required: true },
      ciphertext: { type: String, required: true } // Khóa AES đã bị mã hóa
    },
    granted_at: { type: Date, default: Date.now },
    granted_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    expires_at: { type: Date } // Temporary access
  }],

  // Versioning for Forward Secrecy
  version: { type: Number, default: 1 },

  // Key Versions - Each version has its own encryption key
  key_versions: [{
    version: { type: Number, required: true },
    created_at: { type: Date, default: Date.now },
    expires_at: { type: Date },
    // Each version has wrapped keys for authorized users
    wrapped_keys: [{
      user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      ephemeral_pub: { type: Object, required: true },
      iv: { type: String, required: true },
      ciphertext: { type: String, required: true }
    }]
  }],
  current_version: { type: Number, default: 1 },

  // Key Rotation Policy
  rotation_policy: {
    auto_rotate: { type: Boolean, default: false },
    rotation_interval_days: { type: Number, default: 90 },
    last_rotation: { type: Date },
    next_rotation: { type: Date }
  },

  // Data Integrity (Rollback Protection)
  checksum: { type: String, required: true },

  // Expiration
  expiration: {
    enabled: { type: Boolean, default: false },
    expires_at: { type: Date },
    auto_delete: { type: Boolean, default: false },
    warning_days: { type: Number, default: 7 }
  },

  // Timestamps
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
  last_accessed: { type: Date }
});

// Indexes for performance
SecretSchema.index({ owner: 1, created_at: -1 });
SecretSchema.index({ 'access_list.user_id': 1 });
SecretSchema.index({ category: 1 });
SecretSchema.index({ 'expiration.expires_at': 1 });

// Update timestamp on save (Mongoose 9.x không cần next() với synchronous operations)
SecretSchema.pre('save', function () {
  this.updated_at = Date.now();
});

module.exports = mongoose.model('Secret', SecretSchema);