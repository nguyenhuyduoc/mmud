const express = require('express');
const router = express.Router();
const Secret = require('../models/Secret');
const User = require('../models/User');

// POST /api/secrets - Tạo bí mật mới
router.post('/', async (req, res) => {
  try {
    const { name, encrypted_data, access_list } = req.body;
    
    // access_list gửi lên từ client đã chứa wrapped_key cho người tạo
    const newSecret = new Secret({
      name,
      encrypted_data,
      access_list
    });

    await newSecret.save();
    res.status(201).json(newSecret);
  } catch (error) {
    res.status(500).json({ message: "Lỗi lưu bí mật" });
  }
});

// GET /api/secrets/:email - Lấy danh sách bí mật user được xem
router.get('/:email', async (req, res) => {
  try {
    const { email } = req.params;
    // Tìm user id
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Tìm tất cả secret mà user này có tên trong access_list
    const secrets = await Secret.find({ "access_list.user_id": user._id });
    
    res.json(secrets);
  } catch (error) {
    res.status(500).json({ message: "Lỗi lấy bí mật" });
  }
});

// PUT /api/secrets/share - Chia sẻ bí mật cho người khác
router.put('/share', async (req, res) => {
  try {
    const { secretId, newAccessEntry } = req.body;

    // Tìm và update: Đẩy (push) thêm người mới vào access_list
    await Secret.findByIdAndUpdate(secretId, {
      $push: { access_list: newAccessEntry }
    });
    req.io.to(newAccessEntry.user_id).emit("new_share", {
        message: "Bạn vừa nhận được một bí mật mới!"
    });
    res.status(200).json({ message: "Chia sẻ thành công" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Lỗi Server khi chia sẻ" });
  }
});

module.exports = router;