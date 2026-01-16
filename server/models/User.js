const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  // Auth Hash: Dùng để login (SHA256 của MasterKey)
  auth_hash: { type: String, required: true },
  // Public Key: Để người khác tìm thấy và share bí mật
  public_key: { type: Object, required: true }, // Lưu dạng JWK Object
  // Encrypted Private Key: Két sắt chứa khóa riêng tư
  encrypted_private_key: {
    iv: { type: String, required: true }, // Hex string
    ciphertext: { type: String, required: true } // Hex string
  },
  // Salt: Dùng để tính Master Key từ Password (nếu không dùng email làm salt)
  salt: { type: String },

  // ✅ ROLLBACK PROTECTION - Version counter incremented on ANY secret modification
  secrets_version: { type: Number, default: 0 },

  // ✅ SWAP PROTECTION - Collection-wide checksum
  collection_checksum: { type: String, default: '' },
  last_checksum_update: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);