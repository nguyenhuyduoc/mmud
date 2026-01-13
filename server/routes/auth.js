const express = require('express');
const router = express.Router();
const User = require('../models/User');

// ---------------------------------------------------
// 1. API ĐĂNG KÝ (Register)
// Nhận toàn bộ dữ liệu mã hóa từ Client và lưu vào kho
// ---------------------------------------------------
router.post('/register', async (req, res) => {
  try {
    const { email, auth_hash, salt, public_key, encrypted_private_key } = req.body;

    // Validate cơ bản
    if (!email || !auth_hash || !salt || !public_key || !encrypted_private_key) {
      return res.status(400).json({ message: "Thiếu thông tin đăng ký" });
    }

    // Kiểm tra trùng email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email đã tồn tại" });
    }

    // Tạo user mới
    const newUser = new User({
      email,
      auth_hash,
      salt,
      public_key,
      encrypted_private_key
    });

    await newUser.save();
    
    console.log(`✅ User registered: ${email}`);
    res.status(201).json({ message: "Đăng ký thành công" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Lỗi Server" });
  }
});

// ---------------------------------------------------
// 2. API LẤY SALT (Get Salt) - Bước 1 của Login
// Client cần Salt để tính lại Master Key trước khi Login
// ---------------------------------------------------
router.get('/salt/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User không tồn tại" });
        }

        // Trả về Salt cho Client
        res.status(200).json({ salt: user.salt });
    } catch (error) {
        res.status(500).json({ message: "Lỗi Server" });
    }
});

// ---------------------------------------------------
// 3. API ĐĂNG NHẬP (Login) - Bước 2 của Login
// Kiểm tra Hash và trả về "Két sắt"
// ---------------------------------------------------
router.post('/login', async (req, res) => {
    try {
        const { email, auth_hash } = req.body;

        // Tìm User
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Email hoặc mật khẩu sai" });
        }

        // So sánh Auth Hash (Server so sánh chuỗi String)
        if (auth_hash !== user.auth_hash) {
            return res.status(400).json({ message: "Email hoặc mật khẩu sai" });
        }

        // Đăng nhập thành công!
        // Trả về các thông tin cần thiết để Client giải mã dữ liệu
        res.status(200).json({
            message: "Login success",
            email: user.email,
            public_key: user.public_key,
            encrypted_private_key: user.encrypted_private_key
            // Client sẽ dùng MasterKey (trong RAM) để giải mã cái này
        });

    } catch (error) {
        res.status(500).json({ message: "Lỗi Server" });
    }
});

module.exports = router;