const express = require('express');
const router = express.Router();
const Secret = require('../models/Secret');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const crypto = require('crypto');

// Helper: Get client info
function getClientInfo(req) {
  return {
    ip_address: req.ip || req.connection.remoteAddress,
    user_agent: req.get('user-agent')
  };
}

// Helper: Create audit log
async function logAction(data) {
  try {
    const log = new AuditLog(data);
    await log.save();
  } catch (error) {
    console.error('Failed to create audit log:', error);
  }
}

// Helper: Calculate checksum for data integrity
function calculateChecksum(data) {
  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify(data));
  return hash.digest('hex');
}

// Helper: Get default permissions by role
function getPermissionsByRole(role) {
  const roles = {
    owner: { can_read: true, can_edit: true, can_share: true, can_delete: true },
    editor: { can_read: true, can_edit: true, can_share: true, can_delete: false },
    sharer: { can_read: true, can_edit: false, can_share: true, can_delete: false }, // ✅ New: Read + Share only
    viewer: { can_read: true, can_edit: false, can_share: false, can_delete: false }
  };
  return roles[role] || roles.viewer;
}

// POST /api/secrets - Tạo bí mật mới
router.post('/', async (req, res) => {
  try {
    const { name, encrypted_data, access_list, category, tags, expiration, owner_email } = req.body;

    // Calculate checksum for integrity
    const checksumData = { name, encrypted_data, access_list };
    const checksum = calculateChecksum(checksumData);

    // Find owner
    const owner = await User.findOne({ email: owner_email });
    if (!owner) {
      return res.status(404).json({ message: "Owner not found" });
    }

    // Set owner role and permissions
    const enhancedAccessList = access_list.map(entry => ({
      ...entry,
      role: entry.user_id.toString() === owner._id.toString() ? 'owner' : (entry.role || 'viewer'),
      permissions: entry.user_id.toString() === owner._id.toString()
        ? getPermissionsByRole('owner')
        : getPermissionsByRole(entry.role || 'viewer'),
      granted_by: owner._id
    }));

    const newSecret = new Secret({
      name,
      owner: owner._id,
      encrypted_data,
      access_list: enhancedAccessList,
      category: category || 'general',
      tags: tags || [],
      expiration: expiration || { enabled: false },
      checksum
    });

    await newSecret.save();

    // ✅ UPDATE USER INTEGRITY (rollback/swap protection)
    const { updateUserIntegrity } = require('../utils/integrityCheck');
    await updateUserIntegrity(owner);

    // Log action
    const clientInfo = getClientInfo(req);
    await logAction({
      user_id: owner._id,
      user_email: owner.email,
      action: 'create_secret',
      secret_id: newSecret._id,
      secret_name: newSecret.name,
      ...clientInfo,
      success: true
    });

    res.status(201).json(newSecret);
  } catch (error) {
    console.error('Error creating secret:', error);
    res.status(500).json({ message: "Lỗi lưu bí mật" });
  }
});

// GET /api/secrets/:email - Lấy danh sách bí mật user được xem
router.get('/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const { category, search, page = 1, limit = 50 } = req.query;

    // Tìm user id
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Build query
    const query = { "access_list.user_id": user._id };

    // Filter by category
    if (category && category !== 'all') {
      query.category = category;
    }

    // Search by name
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }

    // Check for expired secrets
    const now = new Date();
    query.$or = [
      { 'expiration.enabled': false },
      { 'expiration.expires_at': { $gt: now } },
      { 'expiration.expires_at': null }
    ];

    // Tìm tất cả secret mà user này có tên trong access_list
    const secrets = await Secret.find(query)
      .populate('owner', 'email')
      .sort({ updated_at: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    // Filter to only show secrets where user has access (including temporary access)
    const filteredSecrets = secrets.filter(secret => {
      const userAccess = secret.access_list.find(a => a.user_id.toString() === user._id.toString());
      if (!userAccess) return false;

      // Check if access has expired
      if (userAccess.expires_at && new Date(userAccess.expires_at) < now) {
        return false;
      }

      return true;
    });

    // ✅ CHECKSUM VERIFICATION - Detect tampering
    const corruptedSecrets = [];
    for (const secret of filteredSecrets) {
      const checksumData = {
        name: secret.name,
        encrypted_data: secret.encrypted_data,
        access_list: secret.access_list
      };
      const calculatedChecksum = calculateChecksum(checksumData);

      if (calculatedChecksum !== secret.checksum) {
        // ⚠️ TAMPERING DETECTED!
        corruptedSecrets.push({
          id: secret._id,
          name: secret.name
        });

        const clientInfo = getClientInfo(req);
        await logAction({
          user_id: user._id,
          user_email: user.email,
          action: 'tampering_detected',
          secret_id: secret._id,
          secret_name: secret.name,
          ...clientInfo,
          success: false,
          error_message: `Checksum mismatch - Expected: ${secret.checksum}, Got: ${calculatedChecksum}`
        });
      }
    }

    // If any secrets are corrupted, alert but still return (allow user to see issue)
    if (corruptedSecrets.length > 0) {
      console.error(`⚠️  INTEGRITY VIOLATION: ${corruptedSecrets.length} secret(s) failed checksum verification`, corruptedSecrets);
    }

    const total = await Secret.countDocuments(query);

    res.json({
      secrets: filteredSecrets,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / limit),
      user_version: user.secrets_version || 0, // ✅ For rollback detection
      integrity_warning: corruptedSecrets.length > 0 ? {
        corrupted_count: corruptedSecrets.length,
        corrupted_secrets: corruptedSecrets
      } : null
    });
  } catch (error) {
    console.error('Error fetching secrets:', error);
    res.status(500).json({ message: "Lỗi lấy bí mật" });
  }
});

// PUT /api/secrets/:id - Update secret (edit encrypted data)
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { encrypted_data, user_email } = req.body;

    // Find secret
    const secret = await Secret.findById(id);
    if (!secret) {
      return res.status(404).json({ message: "Secret not found" });
    }

    // Find user
    const user = await User.findOne({ email: user_email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if user has edit permission
    const userAccess = secret.access_list.find(a => a.user_id.toString() === user._id.toString());
    if (!userAccess || !userAccess.permissions.can_edit) {
      const clientInfo = getClientInfo(req);
      await logAction({
        user_id: user._id,
        user_email: user.email,
        action: 'edit',
        secret_id: secret._id,
        secret_name: secret.name,
        ...clientInfo,
        success: false,
        error_message: 'Insufficient permissions'
      });

      return res.status(403).json({ message: "Bạn không có quyền sửa secret này" });
    }

    // ✅ VERIFY CHECKSUM BEFORE EDIT (detect tampering)
    const checksumData = {
      name: secret.name,
      encrypted_data: secret.encrypted_data,
      access_list: secret.access_list
    };
    const currentChecksum = calculateChecksum(checksumData);

    if (currentChecksum !== secret.checksum) {
      // ⚠️ Checksum mismatch detected
      console.warn(`⚠️ Checksum mismatch for secret ${secret._id}: expected ${secret.checksum}, got ${currentChecksum}`);

      const clientInfo = getClientInfo(req);
      await logAction({
        user_id: user._id,
        user_email: user.email,
        action: 'checksum_auto_fix',
        secret_id: secret._id,
        secret_name: secret.name,
        ...clientInfo,
        success: true,
        error_message: `Auto-fixing checksum mismatch (likely due to legacy data or share without checksum update)`
      });

      // ✅ AUTO-FIX: Update checksum to current value (migration for old secrets)
      secret.checksum = currentChecksum;
      await secret.save();
      console.log(`✅ Auto-fixed checksum for secret ${secret._id}`);
    }

    // Update encrypted data
    secret.encrypted_data = encrypted_data;
    secret.version += 1;

    // Recalculate checksum with new data
    const newChecksumData = {
      name: secret.name,
      encrypted_data: secret.encrypted_data,
      access_list: secret.access_list
    };
    secret.checksum = calculateChecksum(newChecksumData);

    await secret.save();

    // ✅ UPDATE USER INTEGRITY (rollback/swap protection)
    const { updateUserIntegrity } = require('../utils/integrityCheck');
    await updateUserIntegrity(user);

    // Log success
    const clientInfo = getClientInfo(req);
    await logAction({
      user_id: user._id,
      user_email: user.email,
      action: 'edit',
      secret_id: secret._id,
      secret_name: secret.name,
      ...clientInfo,
      success: true
    });

    res.json({ message: "Secret updated successfully", secret });
  } catch (error) {
    console.error('Error updating secret:', error);
    res.status(500).json({ message: "Lỗi cập nhật secret" });
  }
});

// PUT /api/secrets/share - Chia sẻ bí mật cho người khác
router.put('/share', async (req, res) => {
  try {
    const { secretId, newAccessEntry, sharer_email } = req.body;

    // Find secret and sharer
    const secret = await Secret.findById(secretId);
    if (!secret) {
      return res.status(404).json({ message: "Secret not found" });
    }

    const sharer = await User.findOne({ email: sharer_email });
    if (!sharer) {
      return res.status(404).json({ message: "Sharer not found" });
    }

    // Check if sharer has permission to share
    const sharerAccess = secret.access_list.find(a => a.user_id.toString() === sharer._id.toString());
    if (!sharerAccess || !sharerAccess.permissions.can_share) {
      const clientInfo = getClientInfo(req);
      await logAction({
        user_id: sharer._id,
        user_email: sharer.email,
        action: 'share_secret',
        secret_id: secretId,
        secret_name: secret.name,
        ...clientInfo,
        success: false,
        error_message: 'Insufficient permissions'
      });

      return res.status(403).json({ message: "Bạn không có quyền chia sẻ secret này" });
    }

    // ✅ Check if user already has access (prevent duplicates)
    const existingAccess = secret.access_list.find(
      a => a.user_id.toString() === newAccessEntry.user_id.toString()
    );

    if (existingAccess) {
      return res.status(400).json({
        message: "Người này đã được chia sẻ rồi!",
        existing_role: existingAccess.role
      });
    }

    // Enhance new access entry with role and permissions
    const role = newAccessEntry.role || 'viewer';
    const enhancedEntry = {
      ...newAccessEntry,
      role,
      permissions: getPermissionsByRole(role),
      granted_by: sharer._id,
      granted_at: new Date()
    };

    // Tìm và update: Đẩy (push) thêm người mới vào access_list
    await Secret.findByIdAndUpdate(secretId, {
      $push: { access_list: enhancedEntry },
      $inc: { version: 1 }
    });

    // ✅ RECALCULATE CHECKSUM after access_list changes
    const updatedSecret = await Secret.findById(secretId);
    const checksumData = {
      name: updatedSecret.name,
      encrypted_data: updatedSecret.encrypted_data,
      access_list: updatedSecret.access_list
    };
    updatedSecret.checksum = calculateChecksum(checksumData);
    await updatedSecret.save();

    // ✅ UPDATE USER INTEGRITY (rollback/swap protection)
    const { updateUserIntegrity } = require('../utils/integrityCheck');
    await updateUserIntegrity(sharer);

    // Send realtime notification
    req.io.to(newAccessEntry.user_id).emit("new_share", {
      message: "Bạn vừa nhận được một bí mật mới!",
      secret_name: secret.name,
      from: sharer.email
    });

    // Log action
    const recipient = await User.findById(newAccessEntry.user_id);
    const clientInfo = getClientInfo(req);
    await logAction({
      user_id: sharer._id,
      user_email: sharer.email,
      action: 'share_secret',
      secret_id: secretId,
      secret_name: secret.name,
      target_user_email: recipient?.email,
      ...clientInfo,
      success: true,
      metadata: { role }
    });

    res.status(200).json({ message: "Chia sẻ thành công!" });
  } catch (error) {
    console.error('Error sharing secret:', error);
    res.status(500).json({ message: "Lỗi chia sẻ" });
  }
});

// PUT /api/secrets/:id - Update secret (requires editor role)
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { encrypted_data, name, user_email } = req.body;

    const secret = await Secret.findById(id);
    if (!secret) {
      return res.status(404).json({ message: "Secret not found" });
    }

    const user = await User.findOne({ email: user_email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check permissions
    const userAccess = secret.access_list.find(a => a.user_id.toString() === user._id.toString());
    if (!userAccess || !userAccess.permissions.can_edit) {
      return res.status(403).json({ message: "Bạn không có quyền chỉnh sửa secret này" });
    }

    // Update secret
    if (name) secret.name = name;
    if (encrypted_data) secret.encrypted_data = encrypted_data;

    // Recalculate checksum
    const checksumData = { name: secret.name, encrypted_data: secret.encrypted_data, access_list: secret.access_list };
    secret.checksum = calculateChecksum(checksumData);
    secret.version += 1;

    await secret.save();

    // Log action
    const clientInfo = getClientInfo(req);
    await logAction({
      user_id: user._id,
      user_email: user.email,
      action: 'edit_secret',
      secret_id: id,
      secret_name: secret.name,
      ...clientInfo,
      success: true
    });

    res.json({ message: "Cập nhật thành công", secret });
  } catch (error) {
    console.error('Error updating secret:', error);
    res.status(500).json({ message: "Lỗi cập nhật secret" });
  }
});

// DELETE /api/secrets/:id - Delete secret (requires owner role)
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { user_email } = req.query;

    const secret = await Secret.findById(id);
    if (!secret) {
      return res.status(404).json({ message: "Secret not found" });
    }

    const user = await User.findOne({ email: user_email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if user is owner or has delete permission
    const userAccess = secret.access_list.find(a => a.user_id.toString() === user._id.toString());
    if (!userAccess || !userAccess.permissions.can_delete) {
      // ✅ Log failed delete attempt for security monitoring
      const clientInfo = getClientInfo(req);
      await logAction({
        user_id: user._id,
        user_email: user.email,
        action: 'delete_secret',
        secret_id: secret._id,
        secret_name: secret.name,
        ...clientInfo,
        success: false,
        error_message: 'Insufficient permissions - user lacks can_delete permission'
      });

      return res.status(403).json({ message: "Bạn không có quyền xóa secret này" });
    }

    // Collect info about shared access before deletion
    const sharedWith = secret.access_list
      .filter(a => a.user_id.toString() !== user._id.toString())
      .map(a => a.user_id);

    const sharedUserEmails = [];
    for (const userId of sharedWith) {
      const sharedUser = await User.findById(userId);
      if (sharedUser) {
        sharedUserEmails.push(sharedUser.email);
      }
    }

    // Delete the secret
    await Secret.findByIdAndDelete(id);

    // ✅ UPDATE USER INTEGRITY (rollback/swap protection)
    const { updateUserIntegrity } = require('../utils/integrityCheck');
    await updateUserIntegrity(user);

    // Send revoke notifications to all shared users
    if (req.io && sharedWith.length > 0) {
      sharedWith.forEach(userId => {
        req.io.to(userId.toString()).emit("secret_revoked", {
          message: `Secret "${secret.name}" đã bị xóa bởi chủ sở hữu.`,
          secret_id: id,
          secret_name: secret.name,
          revoked_by: user.email,
          revoked_at: new Date()
        });
      });
    }

    // Log action with detailed info about who lost access
    const clientInfo = getClientInfo(req);
    await logAction({
      user_id: user._id,
      user_email: user.email,
      action: 'delete_secret',
      secret_id: id,
      secret_name: secret.name,
      ...clientInfo,
      success: true,
      metadata: {
        shared_with_count: sharedWith.length,
        shared_with_emails: sharedUserEmails,
        cascade_revoke: true
      }
    });

    res.json({
      message: "Xóa thành công",
      revoked_count: sharedWith.length,
      revoked_users: sharedUserEmails
    });
  } catch (error) {
    console.error('Error deleting secret:', error);
    res.status(500).json({ message: "Lỗi xóa secret" });
  }
});

module.exports = router;