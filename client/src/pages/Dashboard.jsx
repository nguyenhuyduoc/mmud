import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { LogOut, Plus, Eye, Share2, Lock, Shield, Users, Clock, Trash2, Edit } from 'lucide-react';
import {
  genRandomSalt,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  HKDF,
  bufferToHex,
  hexToBuffer,
  cryptoKeyToJSON,
  HMACtoAESKey
} from '../utils/lib';
import SecretStrengthIndicator from '../components/SecretStrengthIndicator';

const Dashboard = () => {
  const navigate = useNavigate();
  const [secrets, setSecrets] = useState([]);
  const [users, setUsers] = useState([]);
  const [myUserId, setMyUserId] = useState('');
  const [newSecretName, setNewSecretName] = useState('');
  const [newSecretValue, setNewSecretValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Edit modal state
  const [editingSecret, setEditingSecret] = useState(null);
  const [editSecretValue, setEditSecretValue] = useState('');
  const [showEditModal, setShowEditModal] = useState(false);

  const myEmail = sessionStorage.getItem('user_email');
  const myPrivKeyJson = sessionStorage.getItem('user_private_key');
  const myPubKeyJson = sessionStorage.getItem('user_public_key');

  useEffect(() => {
    if (!myEmail) {
      navigate('/login');
    } else {
      fetchInitialData();
    }
  }, [myEmail, navigate]);

  //  INTEGRITY VERIFICATION HELPER
  const verifyIntegrity = (response, skipAlert = false) => {
    // Check for integrity warnings from server
    if (response.data.integrity_warning && !skipAlert) {
      const warning = response.data.integrity_warning;
      console.error(' INTEGRITY WARNING:', warning);
      alert(
        ` DATA INTEGRITY ISSUE DETECTED!\n\n` +
        `${warning.corrupted_count} secret(s) failed checksum verification.\n\n` +
        `This may indicate:\n` +
        `- Database tampering\n` +
        `- Data corruption\n` +
        `- Unauthorized modifications\n\n` +
        `Affected secrets: ${warning.corrupted_secrets.map(s => s.name).join(', ')}\n\n` +
        `Please contact your administrator immediately.`
      );
    }

    // Check user's version counter (rollback detection)
    const currentVersion = response.data.user_version;
    const storedVersion = localStorage.getItem(`user_secrets_version_${myEmail}`);

    if (storedVersion && currentVersion && parseInt(currentVersion) < parseInt(storedVersion)) {
      console.error('ROLLBACK DETECTED: Version mismatch');
      if (!skipAlert) {
        alert(
          `POTENTIAL ROLLBACK ATTACK DETECTED!\n\n` +
          `Expected version: ${storedVersion}\n` +
          `Received version: ${currentVersion}\n\n` +
          `Your data may have been restored to an older state.\n` +
          `This could indicate a security breach.\n\n` +
          `Please verify your secrets and contact support immediately.`
        );
      }
    } else if (currentVersion) {
      // Store current version for future checks
      localStorage.setItem(`user_secrets_version_${myEmail}`, currentVersion.toString());
    }
  };

  const fetchInitialData = async (skipIntegrityAlert = false) => {
    try {
      const usersRes = await axios.get('http://localhost:5000/api/users');
      setUsers(usersRes.data);
      const me = usersRes.data.find(u => u.email === myEmail);
      if (me) setMyUserId(me._id);

      const secretsRes = await axios.get(`http://localhost:5000/api/secrets/${myEmail}`);

      //  VERIFY INTEGRITY (skip alert right after delete/edit)
      verifyIntegrity(secretsRes, skipIntegrityAlert);

      const secretsData = secretsRes.data.secrets || secretsRes.data;
      setSecrets(Array.isArray(secretsData) ? secretsData : []);
    } catch (err) {
      console.error("Lỗi tải dữ liệu", err);
      setSecrets([]);
    }
  };

  const getSaltKey = async () => {
    return await crypto.subtle.importKey(
      "raw",
      new Uint8Array(32),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  };

  const getSecretKey = async (secret) => {
    const myAccess = secret.access_list.find(a => a.user_id === myUserId);
    if (!myAccess) throw new Error("Không có quyền truy cập");

    const { wrapped_key } = myAccess;
    const myPrivCrypto = await crypto.subtle.importKey(
      "jwk", JSON.parse(myPrivKeyJson),
      { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]
    );

    const ephPubCrypto = await crypto.subtle.importKey(
      "jwk", wrapped_key.ephemeral_pub,
      { name: "ECDH", namedCurve: "P-384" }, true, []
    );

    const sharedSecret = await computeDH(myPrivCrypto, ephPubCrypto);
    const saltKey = await getSaltKey();
    const [hmacWrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
    const aesWrappingKey = await HMACtoAESKey(hmacWrappingKey, "derivation");

    const keyK_ArrayBuffer = await decryptWithGCM(
      aesWrappingKey,
      hexToBuffer(wrapped_key.ciphertext),
      hexToBuffer(wrapped_key.iv),
      "",
      true
    );

    return keyK_ArrayBuffer;
  };

  const handleCreateSecret = async (e) => {
    e.preventDefault();
    if (!newSecretName.trim() || !newSecretValue.trim()) {
      return alert("Vui lòng nhập đầy đủ thông tin!");
    }

    setLoading(true);
    try {
      const keyK = genRandomSalt(32);
      const ivData = genRandomSalt(12);
      const keyK_Crypto = await crypto.subtle.importKey(
        "raw", keyK, "AES-GCM", true, ["encrypt", "decrypt"]
      );
      const encryptedData = await encryptWithGCM(keyK_Crypto, newSecretValue, ivData);

      const myPubCrypto = await crypto.subtle.importKey(
        "jwk", JSON.parse(myPubKeyJson),
        { name: "ECDH", namedCurve: "P-384" }, true, []
      );

      const ephKeyPair = await generateEG();
      const sharedSecret = await computeDH(ephKeyPair.sec, myPubCrypto);
      const saltKey = await getSaltKey();
      const [wrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
      const aesWrappingKey = await HMACtoAESKey(wrappingKey, "derivation");
      const ivKey = genRandomSalt(12);
      const wrappedK = await encryptWithGCM(aesWrappingKey, keyK, ivKey);

      const payload = {
        name: newSecretName,
        owner_email: myEmail,
        encrypted_data: {
          iv: bufferToHex(ivData),
          ciphertext: bufferToHex(encryptedData)
        },
        access_list: [{
          user_id: myUserId,
          wrapped_key: {
            ephemeral_pub: await cryptoKeyToJSON(ephKeyPair.pub),
            iv: bufferToHex(ivKey),
            ciphertext: bufferToHex(wrappedK)
          }
        }],
        category: 'general',
        tags: []
      };

      await axios.post('http://localhost:5000/api/secrets', payload);

      setNewSecretName('');
      setNewSecretValue('');
      setShowCreateForm(false);

      //  Skip integrity alert right after create (version increment is intentional)
      await fetchInitialData(true);
      alert(" Tạo bí mật thành công!");
    } catch (err) {
      console.error(err);
      alert(" Lỗi tạo bí mật: " + (err.response?.data?.message || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleViewSecret = async (secret) => {
    try {
      const keyK_ArrayBuffer = await getSecretKey(secret);
      const keyK_Crypto = await crypto.subtle.importKey(
        "raw", keyK_ArrayBuffer, "AES-GCM", true, ["decrypt"]
      );

      const plaintext = await decryptWithGCM(
        keyK_Crypto,
        hexToBuffer(secret.encrypted_data.ciphertext),
        hexToBuffer(secret.encrypted_data.iv)
      );

      alert(` NỘI DUNG: ${plaintext}`);
    } catch (err) {
      console.error(err);
      alert(" Không thể giải mã (Có thể bạn không có quyền)");
    }
  };

  const handleShareSecret = async (secret, recipientEmail, selectedRole) => {
    if (!recipientEmail) return alert("Vui lòng chọn người nhận!");
    if (!selectedRole) selectedRole = 'viewer'; // Default to viewer

    const recipient = users.find(u => u.email === recipientEmail);
    if (!recipient) return alert(" Email không tồn tại!");

    if (secret.access_list.some(a => a.user_id === recipient._id)) {
      return alert(" Người này đã được chia sẻ rồi!");
    }

    setLoading(true);
    try {
      const keyK_ArrayBuffer = await getSecretKey(secret);
      const recipientPubCrypto = await crypto.subtle.importKey(
        "jwk", recipient.public_key,
        { name: "ECDH", namedCurve: "P-384" }, true, []
      );

      const ephKeyPair = await generateEG();
      const sharedSecret = await computeDH(ephKeyPair.sec, recipientPubCrypto);
      const saltKey = await getSaltKey();
      const [hmacWrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
      const aesWrappingKey = await HMACtoAESKey(hmacWrappingKey, "derivation");
      const ivKey = genRandomSalt(12);
      const wrappedK = await encryptWithGCM(aesWrappingKey, keyK_ArrayBuffer, ivKey);

      await axios.put('http://localhost:5000/api/secrets/share', {
        secretId: secret._id,
        sharer_email: myEmail,
        newAccessEntry: {
          user_id: recipient._id,
          role: selectedRole, // Use selected role instead of hardcoded 'viewer'
          wrapped_key: {
            ephemeral_pub: await cryptoKeyToJSON(ephKeyPair.pub),
            iv: bufferToHex(ivKey),
            ciphertext: bufferToHex(wrappedK)
          }
        }
      });

      fetchInitialData();
      const roleNames = {
        viewer: 'Chỉ xem',
        sharer: 'Xem + Chia sẻ',
        editor: 'Xem + Sửa + Chia sẻ'
      };
      alert(` Chia sẻ thành công với quyền: ${roleNames[selectedRole]}!`);
    } catch (err) {
      console.error(err);
      alert(" Lỗi chia sẻ: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle Edit Secret
  const handleEditSecret = async (secret) => {
    try {
      // Decrypt secret to show current value
      const keyK_ArrayBuffer = await getSecretKey(secret);
      const keyK_Crypto = await crypto.subtle.importKey(
        "raw", keyK_ArrayBuffer, "AES-GCM", true, ["decrypt"]
      );

      const plaintext = await decryptWithGCM(
        keyK_Crypto,
        hexToBuffer(secret.encrypted_data.ciphertext),
        hexToBuffer(secret.encrypted_data.iv)
      );

      // Open edit modal
      setEditingSecret(secret);
      setEditSecretValue(plaintext);
      setShowEditModal(true);
    } catch (err) {
      console.error(err);
      alert(" Không thể giải mã secret để chỉnh sửa!");
    }
  };

  // Save edited secret
  const handleSaveEdit = async () => {
    if (!editingSecret || !editSecretValue.trim()) {
      return alert("Giá trị không được để trống!");
    }

    setLoading(true);
    try {
      // Re-encrypt with existing key
      const keyK_ArrayBuffer = await getSecretKey(editingSecret);
      const keyK_Crypto = await crypto.subtle.importKey(
        "raw", keyK_ArrayBuffer, "AES-GCM", true, ["encrypt"]
      );

      const ivData = genRandomSalt(12);
      const encryptedData = await encryptWithGCM(keyK_Crypto, editSecretValue, ivData);

      // Update secret on server
      await axios.put(`http://localhost:5000/api/secrets/${editingSecret._id}`, {
        encrypted_data: {
          iv: bufferToHex(ivData),
          ciphertext: bufferToHex(encryptedData)
        },
        user_email: myEmail
      });
      // Close modal and refresh
      setShowEditModal(false);
      setEditingSecret(null);
      setEditSecretValue('');

      // Skip integrity alert right after edit (version increment is intentional)
      await fetchInitialData(true);
      alert(" Cập nhật secret thành công!");
    } catch (err) {
      console.error(err);
      alert(" Lỗi cập nhật secret: " + (err.response?.data?.message || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSecret = async (secret) => {
    // Check if user is owner (must have can_delete permission)
    const userAccess = secret.access_list.find(a => a.user_id === myUserId);
    if (!userAccess || !userAccess.permissions?.can_delete) {
      return alert(" Bạn không có quyền xóa secret này! Chỉ chủ sở hữu mới có thể xóa.");
    }

    // Build warning message based on sharing status
    const sharedCount = secret.access_list.length - 1;
    let warningMessage = ` Bạn chắc chắn muốn xóa bí mật "${secret.name}" không?\n\n`;

    if (sharedCount > 0) {
      const sharedWith = secret.access_list
        .filter(a => a.user_id !== myUserId)
        .map(a => users.find(u => u._id === a.user_id)?.email || 'Unknown')
        .join(', ');

      warningMessage += ` CẢNH BÁO: Secret này đã chia sẻ cho ${sharedCount} người:\n`;
      warningMessage += `${sharedWith}\n\n`;
      warningMessage += `Khi bạn xóa, tất cả những người này sẽ MẤT QUYỀN TRUY CẬP ngay lập tức!\n\n`;
    }

    warningMessage += `Hành động này KHÔNG THỂ HOÀN TÁC!`;

    // Confirm before delete
    const confirmDelete = window.confirm(warningMessage);
    if (!confirmDelete) return;

    setLoading(true);
    try {
      await axios.delete(`http://localhost:5000/api/secrets/${secret._id}`, {
        params: { user_email: myEmail }
      });

      // Skip integrity alert right after delete (version increment is intentional)
      await fetchInitialData(true);
      alert(" Đã xóa bí mật thành công!");
    } catch (err) {
      console.error(err);
      alert(" Lỗi xóa bí mật: " + (err.response?.data?.message || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.pageContainer}>
      {/* Animated Background */}
      <div style={styles.bgDecoration1}></div>
      <div style={styles.bgDecoration2}></div>

      <div style={styles.container}>
        {/* SIDEBAR */}
        <div style={styles.sidebar}>
          <div style={styles.sidebarHeader}>
            <div style={styles.logoContainer}>
              <Shield size={32} color="white" strokeWidth={2.5} />
            </div>
            <h2 style={styles.brandTitle}>TeamVault</h2>
            <p style={styles.brandSubtitle}>Zero-Knowledge Vault</p>
          </div>

          <div style={styles.userInfo}>
            <div style={styles.userAvatar}>
              {myEmail?.charAt(0).toUpperCase()}
            </div>
            <div style={styles.userDetails}>
              <div style={styles.userName}>Xin chào!</div>
              <div style={styles.userEmail}>{myEmail}</div>
            </div>
          </div>

          <div style={styles.statsGrid}>
            <div style={styles.statItem}>
              <Lock size={20} style={styles.statIcon} />
              <div>
                <div style={styles.statValue}>{secrets.length}</div>
                <div style={styles.statLabel}>Secrets</div>
              </div>
            </div>
            <div style={styles.statItem}>
              <Users size={20} style={styles.statIcon} />
              <div>
                <div style={styles.statValue}>{users.length}</div>
                <div style={styles.statLabel}>Team</div>
              </div>
            </div>
          </div>

          <div style={styles.featureList}>
            <div style={styles.featureItem}>
              <div style={styles.featureDot}></div>
              <span>End-to-End Encryption</span>
            </div>
            <div style={styles.featureItem}>
              <div style={styles.featureDot}></div>
              <span>ECDH + AES-GCM 256</span>
            </div>
            <div style={styles.featureItem}>
              <div style={styles.featureDot}></div>
              <span>Zero-Knowledge</span>
            </div>
          </div>

          <button onClick={() => { sessionStorage.clear(); navigate('/login'); }} style={styles.logoutBtn}>
            <LogOut size={18} />
            <span>Đăng xuất</span>
          </button>
        </div>

        {/* MAIN CONTENT */}
        <div style={styles.mainContent}>
          <div style={styles.contentHeader}>
            <div>
              <h1 style={styles.pageTitle}>Kho Bí Mật</h1>
              <p style={styles.pageSubtitle}>Quản lý và chia sẻ thông tin bảo mật</p>
            </div>
          </div>

          {/* CREATE SECRET CARD */}
          <div style={styles.createCard}>
            <div style={styles.createHeader}>
              <div style={styles.createIcon}>
                <Plus size={24} color="#667eea" />
              </div>
              <div>
                <h3 style={styles.createTitle}>Tạo Bí Mật Mới</h3>
                <p style={styles.createSubtitle}>Mã hóa và lưu trữ thông tin nhạy cảm</p>
              </div>
            </div>

            <form onSubmit={handleCreateSecret} style={styles.createForm}>
              <div style={styles.formRow}>
                <input
                  placeholder="Tên bí mật (VD: API Key AWS)"
                  value={newSecretName}
                  onChange={e => setNewSecretName(e.target.value)}
                  required
                  style={styles.formInput}
                />
                <input
                  placeholder="Giá trị bí mật"
                  type="password"
                  value={newSecretValue}
                  onChange={e => setNewSecretValue(e.target.value)}
                  required
                  style={{ ...styles.formInput, flex: 2 }}
                />
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    ...styles.createButton,
                    opacity: loading ? 0.7 : 1,
                    cursor: loading ? 'not-allowed' : 'pointer'
                  }}
                >
                  {loading ? (
                    <div style={styles.spinner}></div>
                  ) : (
                    <>
                      <Lock size={18} />
                      <span>Mã hóa & Lưu</span>
                    </>
                  )}
                </button>
              </div>
              {newSecretValue && <SecretStrengthIndicator value={newSecretValue} />}
            </form>
          </div>

          {/* SECRETS GRID */}
          <div style={styles.secretsSection}>
            <div style={styles.sectionHeader}>
              <h3 style={styles.sectionTitle}>Danh Sách Bí Mật</h3>
              <div style={styles.badge}>{secrets.length} bí mật</div>
            </div>

            {secrets.length === 0 ? (
              <div style={styles.emptyState}>
                <Shield size={64} color="#e5e7eb" />
                <h3 style={styles.emptyTitle}>Chưa có bí mật nào</h3>
                <p style={styles.emptyText}>Tạo bí mật đầu tiên để bắt đầu!</p>
              </div>
            ) : (
              <div style={styles.secretsGrid}>
                {secrets.map(sec => (
                  <div key={sec._id} style={styles.secretCard}>
                    <div style={styles.secretHeader}>
                      <div style={styles.secretIconBg}>
                        <Lock size={20} color="#667eea" />
                      </div>
                      <div style={styles.secretInfo}>
                        <h4 style={styles.secretName}>{sec.name}</h4>
                        <div style={styles.secretMeta}>
                          <Clock size={12} />
                          <span>{new Date(sec.created_at).toLocaleDateString('vi-VN')}</span>
                        </div>
                      </div>
                      {/* Delete button in header */}
                      {sec.access_list.find(a => a.user_id === myUserId)?.permissions?.can_delete && (
                        <button
                          onClick={() => handleDeleteSecret(sec)}
                          style={styles.deleteButtonHeader}
                          title="Xóa bí mật này"
                        >
                          <Trash2 size={18} />
                        </button>
                      )}
                    </div>

                    {/* First row: Shared badge + View button */}
                    <div style={styles.topActionRow}>
                      {sec.access_list?.length > 1 ? (
                        <div style={styles.sharedBadge}>
                          <Users size={14} />
                          <span>Chia sẻ với {sec.access_list.length - 1} người</span>
                        </div>
                      ) : (
                        <div style={styles.spacer}></div>
                      )}

                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button onClick={() => handleViewSecret(sec)} style={styles.actionButton}>
                          <Eye size={16} />
                          <span>Xem</span>
                        </button>

                        {/* Edit button - only for owner and editors */}
                        {sec.access_list.find(a => a.user_id === myUserId)?.permissions?.can_edit && (
                          <button onClick={() => handleEditSecret(sec)} style={styles.editButton}>
                            <Edit size={16} />
                            <span>Sửa</span>
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Second row: Share section - only if user has can_share permission */}
                    {sec.access_list.find(a => a.user_id === myUserId)?.permissions?.can_share && (
                      <div style={styles.shareSection}>
                        <div style={styles.shareRow}>
                          <select id={`share-user-${sec._id}`} style={styles.shareSelect}>
                            <option value="">Người nhận</option>
                            {users
                              .filter(u => u.email !== myEmail)
                              .map(u => (
                                <option key={u._id} value={u.email}>{u.email}</option>
                              ))}
                          </select>
                          <select id={`share-role-${sec._id}`} style={styles.shareRoleSelect}>
                            <option value="viewer">🔒 Chỉ xem</option>
                            <option value="sharer">🔓 Xem + Share</option>
                            <option value="editor">✏️ Sửa + Share</option>
                          </select>
                        </div>
                        <button
                          onClick={() => {
                            const email = document.getElementById(`share-user-${sec._id}`).value;
                            const role = document.getElementById(`share-role-${sec._id}`).value;
                            handleShareSecret(sec, email, role);
                          }}
                          style={styles.shareButton}
                        >
                          <Share2 size={16} />
                          <span>Chia sẻ</span>
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Edit Modal */}
      {showEditModal && (
        <div style={styles.modalOverlay} onClick={() => setShowEditModal(false)}>
          <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={styles.modalTitle}>Chỉnh sửa Secret: {editingSecret?.name}</h3>
              <button onClick={() => setShowEditModal(false)} style={styles.modalCloseBtn}>✕</button>
            </div>

            <div style={styles.modalBody}>
              <label style={styles.modalLabel}>Giá trị mới:</label>
              <textarea
                value={editSecretValue}
                onChange={(e) => setEditSecretValue(e.target.value)}
                style={styles.modalTextarea}
                placeholder="Nhập giá trị secret mới"
                rows={4}
              />
            </div>

            <div style={styles.modalFooter}>
              <button
                onClick={() => setShowEditModal(false)}
                style={styles.modalCancelBtn}
              >
                Hủy
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={loading}
                style={{ ...styles.modalSaveBtn, opacity: loading ? 0.7 : 1 }}
              >
                {loading ? 'Đang lưu...' : 'Lưu thay đổi'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div >
  );
};

const styles = {
  pageContainer: {
    minHeight: '100vh',
    background: '#f8f9fc',
    position: 'relative',
    overflow: 'hidden'
  },
  bgDecoration1: {
    position: 'absolute',
    width: '600px',
    height: '600px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(102, 126, 234, 0.15) 0%, transparent 70%)',
    top: '-200px',
    right: '-200px',
    pointerEvents: 'none'
  },
  bgDecoration2: {
    position: 'absolute',
    width: '500px',
    height: '500px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(118, 75, 162, 0.1) 0%, transparent 70%)',
    bottom: '-150px',
    left: '-150px',
    pointerEvents: 'none'
  },
  container: {
    display: 'flex',
    minHeight: '100vh',
    position: 'relative',
    zIndex: 1
  },
  sidebar: {
    width: '320px',
    background: 'linear-gradient(180deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    padding: '32px 24px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    height: '100vh',
    boxShadow: '4px 0 24px rgba(102, 126, 234, 0.2)',
    overflowY: 'auto'
  },
  sidebarHeader: {
    marginBottom: '32px',
    textAlign: 'center'
  },
  logoContainer: {
    width: '64px',
    height: '64px',
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    borderRadius: '16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 16px auto',
    backdropFilter: 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.3)'
  },
  brandTitle: {
    fontSize: '24px',
    fontWeight: 'bold',
    margin: '0 0 4px 0'
  },
  brandSubtitle: {
    fontSize: '13px',
    opacity: 0.9,
    margin: 0
  },
  userInfo: {
    backgroundColor: 'rgba(255, 255, 255, 0.15)',
    borderRadius: '12px',
    padding: '16px',
    marginBottom: '24px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    backdropFilter: 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.2)'
  },
  userAvatar: {
    width: '48px',
    height: '48px',
    borderRadius: '12px',
    backgroundColor: 'rgba(255, 255, 255, 0.3)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '20px',
    fontWeight: 'bold'
  },
  userDetails: {
    flex: 1,
    overflow: 'hidden'
  },
  userName: {
    fontSize: '14px',
    fontWeight: '600',
    marginBottom: '2px'
  },
  userEmail: {
    fontSize: '12px',
    opacity: 0.9,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '12px',
    marginBottom: '24px'
  },
  statItem: {
    backgroundColor: 'rgba(255, 255, 255, 0.15)',
    borderRadius: '10px',
    padding: '12px',
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    backdropFilter: 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.2)'
  },
  statIcon: {
    opacity: 0.9
  },
  statValue: {
    fontSize: '20px',
    fontWeight: 'bold',
    lineHeight: '1'
  },
  statLabel: {
    fontSize: '11px',
    opacity: 0.85,
    marginTop: '2px'
  },
  featureList: {
    flex: 1,
    marginBottom: '24px'
  },
  featureItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    fontSize: '13px',
    marginBottom: '10px',
    opacity: 0.9
  },
  featureDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: '#10b981'
  },
  logoutBtn: {
    width: '100%',
    padding: '12px',
    background: 'rgba(255, 255, 255, 0.2)',
    color: 'white',
    border: '1px solid rgba(255, 255, 255, 0.3)',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '600',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    transition: 'all 0.2s',
    backdropFilter: 'blur(10px)'
  },
  mainContent: {
    flex: 1,
    padding: '40px',
    overflowY: 'auto'
  },
  contentHeader: {
    marginBottom: '32px'
  },
  pageTitle: {
    fontSize: '32px',
    fontWeight: 'bold',
    color: '#1f2937',
    margin: '0 0 4px 0'
  },
  pageSubtitle: {
    fontSize: '14px',
    color: '#6b7280',
    margin: 0
  },
  createCard: {
    backgroundColor: 'white',
    borderRadius: '16px',
    padding: '24px',
    marginBottom: '32px',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)',
    border: '1px solid #e5e7eb'
  },
  createHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
    marginBottom: '20px'
  },
  createIcon: {
    width: '48px',
    height: '48px',
    borderRadius: '12px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    opacity: 0.1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  createTitle: {
    fontSize: '18px',
    fontWeight: 'bold',
    color: '#1f2937',
    margin: '0 0 4px 0'
  },
  createSubtitle: {
    fontSize: '13px',
    color: '#6b7280',
    margin: 0
  },
  createForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  formRow: {
    display: 'flex',
    gap: '12px',
    alignItems: 'center'
  },
  formInput: {
    flex: 1,
    padding: '12px 16px',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '14px',
    transition: 'all 0.2s',
    outline: 'none'
  },
  createButton: {
    padding: '12px 24px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    fontSize: '14px',
    fontWeight: '600',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    whiteSpace: 'nowrap',
    transition: 'all 0.3s',
    boxShadow: '0 4px 12px rgba(102, 126, 234, 0.3)'
  },
  spinner: {
    width: '18px',
    height: '18px',
    border: '3px solid rgba(255, 255, 255, 0.3)',
    borderTop: '3px solid white',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite'
  },
  secretsSection: {
    backgroundColor: 'white',
    borderRadius: '16px',
    padding: '24px',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.08)',
    border: '1px solid #e5e7eb'
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '20px'
  },
  sectionTitle: {
    fontSize: '18px',
    fontWeight: 'bold',
    color: '#1f2937',
    margin: 0
  },
  badge: {
    padding: '6px 12px',
    backgroundColor: '#f3f4f6',
    borderRadius: '20px',
    fontSize: '13px',
    fontWeight: '600',
    color: '#6b7280'
  },
  emptyState: {
    textAlign: 'center',
    padding: '60px 20px',
    color: '#9ca3af'
  },
  emptyTitle: {
    fontSize: '18px',
    color: '#6b7280',
    margin: '16px 0 8px 0'
  },
  emptyText: {
    fontSize: '14px',
    margin: 0
  },
  secretsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
    gap: '20px',
    maxHeight: 'calc(100vh - 400px)',
    overflowY: 'auto',
    padding: '4px',
    alignItems: 'stretch', // Ensure all grid items stretch to same height
    scrollBehavior: 'smooth'
  },
  secretCard: {
    backgroundColor: '#f9fafb',
    borderRadius: '12px',
    padding: '20px',
    border: '2px solid #e5e7eb',
    transition: 'all 0.2s',
    display: 'flex',
    flexDirection: 'column',
    minHeight: '280px' // Consistent minimum height
  },
  secretHeader: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '12px',
    marginBottom: '12px',
    position: 'relative',
    minHeight: '60px' // Consistent header height
  },
  secretIconBg: {
    width: '40px',
    height: '40px',
    borderRadius: '10px',
    background: 'linear-gradient(135deg, #667eea20 0%, #764ba220 100%)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0
  },
  secretInfo: {
    flex: 1,
    overflow: 'hidden'
  },
  secretName: {
    fontSize: '16px',
    fontWeight: '600',
    color: '#1f2937',
    margin: '0 0 6px 0',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  },
  secretMeta: {
    fontSize: '12px',
    color: '#9ca3af',
    display: 'flex',
    alignItems: 'center',
    gap: '4px'
  },
  sharedBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '6px 10px',
    backgroundColor: '#dbeafe',
    color: '#1e40af',
    borderRadius: '6px',
    fontSize: '12px',
    fontWeight: '500',
    marginBottom: '12px'
  },
  topActionRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px',
    minHeight: '32px'
  },
  spacer: {
    flex: 1
  },
  secretActions: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
    flexWrap: 'wrap',
    alignItems: 'center'
  },
  actionButton: {
    padding: '8px 16px',
    backgroundColor: 'white',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: '500',
    color: '#374151',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    transition: 'all 0.2s',
    flexShrink: 0,
    whiteSpace: 'nowrap'
  },
  editButton: {
    padding: '8px 16px',
    backgroundColor: '#fef3c7',
    border: '2px solid #fbbf24',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: '500',
    color: '#92400e',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    transition: 'all 0.2s',
    flexShrink: 0,
    whiteSpace: 'nowrap'
  },
  shareSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    width: '100%'
  },
  shareRow: {
    display: 'flex',
    gap: '8px',
    width: '100%'
  },
  shareSelect: {
    flex: 1,
    padding: '8px 12px',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '13px',
    backgroundColor: 'white',
    cursor: 'pointer',
    outline: 'none'
  },
  shareRoleSelect: {
    flex: 1,
    padding: '8px 12px',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '13px',
    backgroundColor: '#f9fafb',
    cursor: 'pointer',
    outline: 'none',
    fontWeight: '500',
    color: '#374151'
  },
  shareButton: {
    width: '100%',
    padding: '8px 12px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s'
  },
  deleteButton: {
    padding: '8px',
    background: '#fee2e2',
    color: '#dc2626',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s',
    flexShrink: 0
  },
  deleteButtonHeader: {
    position: 'absolute',
    top: '0',
    right: '0',
    padding: '8px',
    background: '#fee2e2',
    color: '#dc2626',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s',
    opacity: 0.8
  },
  // Edit Modal Styles
  modalOverlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000
  },
  modalContent: {
    backgroundColor: 'white',
    borderRadius: '16px',
    padding: '0',
    width: '90%',
    maxWidth: '500px',
    boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)',
    animation: 'slideUp 0.3s ease'
  },
  modalHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px 24px',
    borderBottom: '2px solid #e5e7eb'
  },
  modalTitle: {
    margin: 0,
    fontSize: '18px',
    fontWeight: '600',
    color: '#1f2937'
  },
  modalCloseBtn: {
    background: 'none',
    border: 'none',
    fontSize: '24px',
    cursor: 'pointer',
    color: '#9ca3af',
    padding: '0',
    width: '32px',
    height: '32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '6px',
    transition: 'all 0.2s'
  },
  modalBody: {
    padding: '24px'
  },
  modalLabel: {
    display: 'block',
    marginBottom: '8px',
    fontSize: '14px',
    fontWeight: '500',
    color: '#374151'
  },
  modalTextarea: {
    width: '100%',
    padding: '12px',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '14px',
    fontFamily: 'inherit',
    resize: 'vertical',
    outline: 'none',
    transition: 'border 0.2s'
  },
  modalFooter: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '12px',
    padding: '20px 24px',
    borderTop: '2px solid #e5e7eb'
  },
  modalCancelBtn: {
    padding: '10px 20px',
    backgroundColor: '#f3f4f6',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
    color: '#374151',
    transition: 'all 0.2s'
  },
  modalSaveBtn: {
    padding: '10px 20px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
    color: 'white',
    transition: 'all 0.2s'
  }
};

const styleSheet = document.createElement('style');
styleSheet.textContent = `
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  
  input:focus {
    border-color: #667eea !important;
  }
  
  button:hover:not(:disabled) {
    transform: translateY(-1px);
  }
  
  .secretCard:hover {
    border-color: #667eea !important;
    box-shadow: 0 4px 16px rgba(102, 126, 234, 0.2) !important;
  }
  
  .logoutBtn:hover {
    background: rgba(255, 255, 255, 0.3) !important;
  }
`;
document.head.appendChild(styleSheet);

export default Dashboard;
