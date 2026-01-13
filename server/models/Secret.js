const mongoose = require('mongoose');

const SecretSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Tên gợi nhớ (VD: "DB Production")
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Người tạo
  
  // Nội dung bí mật đã mã hóa (AES-GCM)
  encrypted_data: {
    iv: { type: String, required: true },
    ciphertext: { type: String, required: true }
  },

  // Danh sách quyền truy cập (Key Wrapping)
  access_list: [{
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    // Khóa giải mã (Wrapped Key) dành riêng cho user này
    wrapped_key: {
      ephemeral_pub: { type: Object, required: true }, // Khóa tạm ECDH
      iv: { type: String, required: true },
      ciphertext: { type: String, required: true } // Khóa AES đã bị mã hóa
    }
  }]
});

module.exports = mongoose.model('Secret', SecretSchema);