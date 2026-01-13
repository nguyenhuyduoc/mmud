import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { io } from "socket.io-client";
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

const Dashboard = () => {
  const navigate = useNavigate();
  const [socket, setSocket] = useState(null);
  // State quản lý dữ liệu
  const [secrets, setSecrets] = useState([]);
  const [users, setUsers] = useState([]); // Danh sách user để lấy ID của chính mình
  const [myUserId, setMyUserId] = useState('');
  
  // State cho form tạo mới
  const [newSecretName, setNewSecretName] = useState('');
  const [newSecretValue, setNewSecretValue] = useState('');
  const [loading, setLoading] = useState(false);

  // Lấy thông tin từ Session
  const myEmail = sessionStorage.getItem('user_email');
  const myPrivKeyJson = sessionStorage.getItem('user_private_key'); // Dạng JSON string
  const myPubKeyJson = sessionStorage.getItem('user_public_key');   // Dạng JSON string
  // Effect khởi tạo Socket
  useEffect(() => {
    if (!myUserId) return;

    // 2. Kết nối tới Server
    const newSocket = io("http://localhost:5000");
    setSocket(newSocket);

    // 3. Xin vào phòng riêng (dùng ID của mình làm tên phòng)
    newSocket.emit("join_room", myUserId);

    // 4. Lắng nghe sự kiện "new_share"
    newSocket.on("new_share", (data) => {
        console.log("🔔 REALTIME UPDATE:", data.message);
        alert(`🔔 Ting Ting! ${data.message}`); // Thông báo cho user biết
        
        // Tự động tải lại dữ liệu mà không cần F5
        fetchInitialData();
    });

    // Cleanup khi thoát trang
    return () => newSocket.disconnect();

  }, [myUserId]);
  useEffect(() => {
    if (!myEmail || !myPrivKeyJson) {
      navigate('/login');
      return;
    }
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      // 1. Lấy danh sách users để tìm ID của mình
      const usersRes = await axios.get('http://localhost:5000/api/users');
      setUsers(usersRes.data);
      const me = usersRes.data.find(u => u.email === myEmail);
      if (me) setMyUserId(me._id);

      // 2. Lấy danh sách bí mật
      const secretsRes = await axios.get(`http://localhost:5000/api/secrets/${myEmail}`);
      setSecrets(secretsRes.data);
    } catch (err) {
      console.error("Lỗi tải dữ liệu", err);
    }
  };

  const getSaltKey = async () => {
    return await crypto.subtle.importKey(
      "raw",
      new Uint8Array(32), // Mảng 32 byte số 0
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  };

  // Helper: Hàm giải mã để lấy ra Khóa K (Raw AES Key) từ một Secret
  const getSecretKey = async (secret) => {
    // 1. Tìm gói khóa của mình
    const myAccess = secret.access_list.find(a => a.user_id === myUserId);
    if (!myAccess) throw new Error("Không có quyền truy cập");

    const { wrapped_key } = myAccess;

    // 2. Khôi phục Private Key của mình
    const myPrivCrypto = await crypto.subtle.importKey(
        "jwk", JSON.parse(myPrivKeyJson), 
        { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]
    );

    // 3. Import Ephemeral Pub Key
    const ephPubCrypto = await crypto.subtle.importKey(
        "jwk", wrapped_key.ephemeral_pub,
        { name: "ECDH", namedCurve: "P-384" }, true, []
    );

    // 4. Tính Shared Secret
    const sharedSecret = await computeDH(myPrivCrypto, ephPubCrypto);

    // 5. Derivation (HKDF -> HMAC -> AES)
    const saltKey = await getSaltKey(); // Hàm bạn đã viết ở bước trước
    const [hmacWrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
    const aesWrappingKey = await HMACtoAESKey(hmacWrappingKey, "derivation");

    // 6. Giải mã lấy K (Binary)
    // LƯU Ý: decryptWithGCM phải có tham số thứ 5 là true (như bài trước đã sửa)
    const keyK_ArrayBuffer = await decryptWithGCM(
        aesWrappingKey, 
        hexToBuffer(wrapped_key.ciphertext),
        hexToBuffer(wrapped_key.iv),
        "", 
        true // returnBinary = true
    );

    return keyK_ArrayBuffer;
  };

  // --- LOGIC 1: TẠO BÍ MẬT MỚI (Encryption & Wrapping) ---
  const handleCreateSecret = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      // B1: Tạo khóa đối xứng K (AES Key) cho bí mật này
      const keyK = genRandomSalt(32); // Random 32 bytes
      
      // B2: Mã hóa nội dung bí mật bằng K
      const ivData = genRandomSalt(12);
      // Import K vào CryptoKey để dùng mã hóa
      const keyK_Crypto = await crypto.subtle.importKey(
          "raw", keyK, "AES-GCM", true, ["encrypt", "decrypt"]
      );
      const encryptedData = await encryptWithGCM(keyK_Crypto, newSecretValue, ivData);

      // B3: "Gói" khóa K cho CHÍNH MÌNH (để sau này mình mở được)
      // Cần Public Key của mình dưới dạng CryptoKey
      const myPubCrypto = await crypto.subtle.importKey(
          "jwk", JSON.parse(myPubKeyJson), 
          { name: "ECDH", namedCurve: "P-384" }, true, []
      );

      // B4: Thực hiện Key Wrapping (ECDH + HKDF + AES)
      // a. Tạo cặp khóa tạm (Ephemeral Keys)
      const ephKeyPair = await generateEG();
      
      // b. Tính Shared Secret (Eph-Priv + My-Pub)
      const sharedSecret = await computeDH(ephKeyPair.sec, myPubCrypto);
      const saltKey = await getSaltKey();
      // c. Dẫn xuất Wrapping Key từ Shared Secret
      const [wrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
      const aesWrappingKey = await HMACtoAESKey(wrappingKey, "derivation");
      // d. Mã hóa khóa K bằng Wrapping Key
      const ivKey = genRandomSalt(12);
      const wrappedK = await encryptWithGCM(aesWrappingKey, keyK, ivKey); // keyK là ArrayBuffer (raw bytes)

      // B5: Đóng gói Payload gửi Server
      const payload = {
        name: newSecretName,
        encrypted_data: {
            iv: bufferToHex(ivData),
            ciphertext: bufferToHex(encryptedData)
        },
        access_list: [
            {
                user_id: myUserId,
                wrapped_key: {
                    ephemeral_pub: await cryptoKeyToJSON(ephKeyPair.pub), // Lưu khóa tạm công khai
                    iv: bufferToHex(ivKey),
                    ciphertext: bufferToHex(wrappedK)
                }
            }
        ]
      };

      await axios.post('http://localhost:5000/api/secrets', payload);
      
      // Reset form & Reload
      setNewSecretName('');
      setNewSecretValue('');
      fetchInitialData();
      alert("Đã tạo bí mật thành công!");

    } catch (err) {
      console.error(err);
      alert("Lỗi tạo bí mật");
    } finally {
      setLoading(false);
    }
  };

  // --- LOGIC 2: XEM BÍ MẬT (Unwrapping & Decryption) ---
  const handleViewSecret = async (secret) => {
    try {
        // 1. Lấy khóa K (dùng helper)
        const keyK_ArrayBuffer = await getSecretKey(secret);

        // 2. Import K để giải mã data
        const keyK_Crypto = await crypto.subtle.importKey(
            "raw", keyK_ArrayBuffer, "AES-GCM", true, ["decrypt"]
        );

        // 3. Giải mã nội dung
        const plaintext = await decryptWithGCM(
            keyK_Crypto,
            hexToBuffer(secret.encrypted_data.ciphertext),
            hexToBuffer(secret.encrypted_data.iv)
        );

        alert(`NỘI DUNG MẬT: ${plaintext}`);
    } catch (err) {
        console.error(err);
        alert("Không thể giải mã (Có thể bạn không có quyền hoặc lỗi khóa).");
    }
  };

  const handleShareSecret = async (secret, recipientEmail) => {
    try {
      if (!recipientEmail) return alert("Chưa chọn người nhận!");
      
      const recipient = users.find(u => u.email === recipientEmail);
      if (!recipient) return alert("Email không tồn tại!");
      
      // Kiểm tra xem người này đã có trong list chưa
      if (secret.access_list.some(a => a.user_id === recipient._id)) {
        return alert("Người này đã được chia sẻ rồi!");
      }

      setLoading(true);

      // BƯỚC 1: LẤY KHÓA K (Của chính mình đang giữ)
      // (Mình phải mở khóa của mình ra trước thì mới gói lại cho người khác được)
      const keyK_ArrayBuffer = await getSecretKey(secret);

      // BƯỚC 2: CHUẨN BỊ GÓI HÀNG CHO NGƯỜI NHẬN
      // a. Lấy Public Key của người nhận (Recipient)
      const recipientPubCrypto = await crypto.subtle.importKey(
          "jwk", recipient.public_key, // Public Key từ DB
          { name: "ECDH", namedCurve: "P-384" }, true, []
      );

      // b. Tạo cặp khóa tạm (Ephemeral Keys)
      const ephKeyPair = await generateEG();

      // c. Tính Shared Secret (Eph-Priv + Recipient-Pub)
      // (Lần này dùng Pub của người nhận, không phải của mình)
      const sharedSecret = await computeDH(ephKeyPair.sec, recipientPubCrypto);

      // d. Tạo Wrapping Key (HKDF -> AES)
      const saltKey = await getSaltKey();
      const [hmacWrappingKey] = await HKDF(sharedSecret, saltKey, "teamvault-wrapping");
      const aesWrappingKey = await HMACtoAESKey(hmacWrappingKey, "derivation");

      // e. Mã hóa khóa K bằng Wrapping Key mới này
      const ivKey = genRandomSalt(12);
      const wrappedK = await encryptWithGCM(aesWrappingKey, keyK_ArrayBuffer, ivKey);

      // BƯỚC 3: GỬI LÊN SERVER
      const newAccessEntry = {
          user_id: recipient._id,
          wrapped_key: {
              ephemeral_pub: await cryptoKeyToJSON(ephKeyPair.pub),
              iv: bufferToHex(ivKey),
              ciphertext: bufferToHex(wrappedK)
          }
      };

      await axios.put('http://localhost:5000/api/secrets/share', {
          secretId: secret._id,
          newAccessEntry
      });

      alert(`Đã chia sẻ thành công cho ${recipientEmail}`);
      fetchInitialData(); // Load lại danh sách

    } catch (err) {
      console.error(err);
      alert("Lỗi khi chia sẻ: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
  <div style={{ display: 'flex', minHeight: '100vh', fontFamily: 'Inter, Arial' }}>
    
    {/* SIDEBAR */}
    <div style={{
      width: '360px',
      background: 'linear-gradient(180deg, #6b73ff, #7e57c2)',
      color: 'white',
      padding: '40px'
    }}>
      <h2 style={{ marginBottom: '10px' }}>🔐 Team Secret Manager</h2>
      <p style={{ opacity: 0.9 }}>Zero-Knowledge Password Vault</p>

      <ul style={{ marginTop: '40px', lineHeight: '2' }}>
        <li>✅ End-to-End Encryption</li>
        <li>✅ ECDH + AES-GCM</li>
        <li>✅ Zero-Knowledge</li>
      </ul>

      <button
        onClick={() => {
          sessionStorage.clear();
          navigate('/login');
        }}
        style={{
          marginTop: '40px',
          padding: '10px',
          width: '100%',
          background: '#fff',
          color: '#6b73ff',
          border: 'none',
          borderRadius: '6px',
          cursor: 'pointer'
        }}
      >
        Đăng xuất
      </button>
    </div>

    {/* MAIN CONTENT */}
    <div style={{ flex: 1, padding: '40px', background: '#f5f7fb' }}>
      <h2>Kho bí mật của bạn</h2>
      <p style={{ color: '#666' }}>{myEmail}</p>

      {/* CREATE SECRET */}
      <div style={{
        background: '#fff',
        padding: '20px',
        borderRadius: '10px',
        marginTop: '20px'
      }}>
        <h3>➕ Tạo bí mật mới</h3>
        <form onSubmit={handleCreateSecret} style={{ display: 'flex', gap: '10px' }}>
          <input
            placeholder="Tên gợi nhớ"
            value={newSecretName}
            onChange={e => setNewSecretName(e.target.value)}
            required
            style={{ flex: 1, padding: '10px' }}
          />
          <input
            placeholder="Nội dung bí mật"
            type="password"
            value={newSecretValue}
            onChange={e => setNewSecretValue(e.target.value)}
            required
            style={{ flex: 2, padding: '10px' }}
          />
          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '10px 20px',
              background: '#6b73ff',
              color: 'white',
              border: 'none',
              borderRadius: '6px'
            }}
          >
            {loading ? 'Đang mã hóa...' : 'Lưu'}
          </button>
        </form>
      </div>

      {/* SECRET LIST */}
      <div style={{
        marginTop: '30px',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '20px'
      }}>
        {secrets.map(sec => (
          <div key={sec._id} style={{
            background: 'white',
            padding: '20px',
            borderRadius: '10px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.08)'
          }}>
            <h4>{sec.name}</h4>

            <button
              onClick={() => handleViewSecret(sec)}
              style={{
                width: '100%',
                marginTop: '10px',
                padding: '8px',
                background: '#4caf50',
                color: 'white',
                border: 'none',
                borderRadius: '6px'
              }}
            >
              🔓 Giải mã & Xem
            </button>

            {/* SHARE */}
            <div style={{ marginTop: '10px' }}>
              <select id={`share-${sec._id}`} style={{ width: '100%', padding: '6px' }}>
                <option value="">Chọn người chia sẻ</option>
                {users
                  .filter(u => u.email !== myEmail)
                  .map(u => (
                    <option key={u._id} value={u.email}>{u.email}</option>
                  ))}
              </select>

              <button
                onClick={() => {
                  const email = document.getElementById(`share-${sec._id}`).value;
                  handleShareSecret(sec, email);
                }}
                style={{
                  marginTop: '6px',
                  width: '100%',
                  padding: '8px',
                  background: '#2196f3',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px'
                }}
              >
                📤 Chia sẻ
              </button>
            </div>

            <small style={{ color: '#888' }}>
              Đã chia sẻ: {sec.access_list.length} người
            </small>
          </div>
        ))}
      </div>
    </div>
  </div>
);

};

export default Dashboard;

