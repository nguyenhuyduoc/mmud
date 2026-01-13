// import { useState } from 'react';
// import axios from 'axios';
// import { useNavigate, Link } from 'react-router-dom';


// import {
//   passwordToMasterKey,
//   deriveAuthHash,
//   generateEG,
//   encryptWithGCM,
//   genRandomSalt,
//   bufferToHex
// } from '../utils/lib';

// const Register = () => {
//   const [email, setEmail] = useState('');
//   const [password, setPassword] = useState('');
//   const [confirmPassword, setConfirmPassword] = useState('');
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState('');
  
//   const navigate = useNavigate();

//   const handleRegister = async (e) => {
//     e.preventDefault();
//     setError('');
//     setLoading(true);

//     if (password !== confirmPassword) {
//       setError("Mật khẩu không khớp!");
//       setLoading(false);
//       return;
//     }

//     try {
//       console.log("🚀 Bắt đầu quy trình Zero-Knowledge Registration...");

//       // --- BƯỚC 1: TẠO MASTER KEY (Client-side only) ---
//       // Tạo một chuỗi Salt ngẫu nhiên để chống Rainbow Table
//       // Salt này sẽ được lưu công khai trên server để dùng lại lúc đăng nhập
//       const salt = genRandomSalt(); 
      
//       console.log("1. Đang tính toán Master Key từ mật khẩu...");
//       // KDF: Password + Salt -> Master Key (Khóa này dùng để giải mã, KHÔNG GỬI ĐI)
//       const masterKey = await passwordToMasterKey(password, salt);
//       console.log(masterKey)
//       // --- BƯỚC 2: TẠO AUTH HASH (Để đăng nhập) ---
//       console.log("2. Đang tạo Auth Hash...");
//       // Hash: Master Key -> Auth Hash (Khóa này gửi Server để check login)
//       const authHash = await deriveAuthHash(masterKey);
//       console.log(authHash)
//       // --- BƯỚC 3: TẠO CẶP KHÓA ĐỊNH DANH (Identity Keys) ---
//       console.log("3. Đang sinh cặp khóa RSA/ElGamal...");
//       const keyPair = await generateEG(); // Trả về { pub: CryptoKey, sec: CryptoKey }

//       // --- BƯỚC 4: XUẤT KHÓA (Export Keys) ---
//       // CryptoKey là object đặc biệt của trình duyệt, không gửi qua mạng được
//       // Phải xuất ra dạng JSON (JWK)
//       const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.pub);
//       const privateKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.sec);

//       // --- BƯỚC 5: MÃ HÓA PRIVATE KEY (Két sắt) ---
//       console.log("4. Đang đóng gói Private Key vào két sắt...");
//       const privKeyJsonString = JSON.stringify(privateKeyJWK);
//       const iv = genRandomSalt(); // Vector khởi tạo cho AES
      
//       // Dùng Master Key để khóa Private Key lại
//       const encryptedPrivateKeyCipher = await encryptWithGCM(
//         masterKey, 
//         privKeyJsonString, 
//         iv
//       );

//       // --- BƯỚC 6: GỬI LÊN SERVER ---
//       const payload = {
//         email: email,
//         auth_hash: authHash,      // Để login
//         salt: bufferToHex(salt),               // Để lần sau tính lại được Master Key
//         public_key: publicKeyJWK, // Để người khác share đồ cho mình
//         encrypted_private_key: {  // Két sắt
//           iv: bufferToHex(iv),
//           ciphertext: bufferToHex(encryptedPrivateKeyCipher)
//         }
//       };

//       console.log("5. Gửi Payload lên API:", payload);
      
//       // Gọi API Backend
//       await axios.post('http://localhost:5000/api/auth/register', payload);
      
//       alert("Đăng ký thành công! Hãy đăng nhập.");
//       navigate('/login');

//     } catch (err) {
//       console.error("Lỗi đăng ký:", err);
//       setError(err.response?.data?.message || "Đã có lỗi xảy ra khi xử lý mật mã.");
//     } finally {
//       setLoading(false);
//     }
//   };

//   return (
//     <div style={styles.container}>
//       <div style={styles.formBox}>
//         <h2>Đăng ký TeamVault</h2>
//         <p style={{marginBottom: '20px', color: '#666'}}>Mô hình Zero-Knowledge</p>
        
//         {error && <div style={styles.error}>{error}</div>}
        
//         <form onSubmit={handleRegister}>
//           <div style={styles.inputGroup}>
//             <label>Email</label>
//             <input 
//               type="email" 
//               required 
//               value={email}
//               onChange={(e) => setEmail(e.target.value)}
//               style={styles.input}
//             />
//           </div>
          
//           <div style={styles.inputGroup}>
//             <label>Mật khẩu</label>
//             <input 
//               type="password" 
//               required 
//               value={password}
//               onChange={(e) => setPassword(e.target.value)}
//               style={styles.input}
//               placeholder="Nhập mật khẩu mạnh..."
//             />
//           </div>

//           <div style={styles.inputGroup}>
//             <label>Nhập lại Mật khẩu</label>
//             <input 
//               type="password" 
//               required 
//               value={confirmPassword}
//               onChange={(e) => setConfirmPassword(e.target.value)}
//               style={styles.input}
//             />
//           </div>

//           <button type="submit" disabled={loading} style={styles.button}>
//             {loading ? 'Đang mã hóa & Đăng ký...' : 'Đăng ký Tài khoản'}
//           </button>
//         </form>
        
//         <p style={{marginTop: '15px'}}>
//           Đã có tài khoản? <Link to="/login">Đăng nhập</Link>
//         </p>
//       </div>
//     </div>
//   );
// };

// // CSS đơn giản (Inline styles) để bạn chạy được ngay
// const styles = {
//   container: {
//     display: 'flex', justifyContent: 'center', alignItems: 'center', 
//     height: '100vh', backgroundColor: '#f0f2f5'
//   },
//   formBox: {
//     padding: '30px', borderRadius: '8px', backgroundColor: 'white',
//     boxShadow: '0 4px 12px rgba(0,0,0,0.1)', width: '400px'
//   },
//   inputGroup: { marginBottom: '15px' },
//   input: {
//     width: '100%', padding: '10px', marginTop: '5px',
//     border: '1px solid #ddd', borderRadius: '4px', boxSizing: 'border-box'
//   },
//   button: {
//     width: '100%', padding: '12px', backgroundColor: '#007bff', color: 'white',
//     border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '16px'
//   },
//   error: {
//     backgroundColor: '#ffebee', color: '#c62828', padding: '10px',
//     borderRadius: '4px', marginBottom: '15px', fontSize: '14px'
//   }
// };

// export default Register;

import { useState } from 'react';
import { Lock, Mail, Eye, EyeOff, Shield, Check } from 'lucide-react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
// Import các hàm crypto từ utils/lib của bạn
import {
  passwordToMasterKey,
  deriveAuthHash,
  generateEG,
  encryptWithGCM,
  genRandomSalt,
  bufferToHex
} from '../utils/lib';

const Register = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const getPasswordStrength = (pass) => {
    if (!pass) return { strength: 0, text: '', color: '' };
    let strength = 0;
    if (pass.length >= 8) strength++;
    if (pass.length >= 12) strength++;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) strength++;
    if (/\d/.test(pass)) strength++;
    if (/[^a-zA-Z0-9]/.test(pass)) strength++;

    const levels = [
      { strength: 0, text: '', color: '' },
      { strength: 1, text: 'Yếu', color: '#ef4444' },
      { strength: 2, text: 'Trung bình', color: '#f59e0b' },
      { strength: 3, text: 'Tốt', color: '#3b82f6' },
      { strength: 4, text: 'Mạnh', color: '#10b981' },
      { strength: 5, text: 'Rất mạnh', color: '#059669' }
    ];
    return levels[strength];
  };

  const passwordStrength = getPasswordStrength(password);

  const handleRegister = async (e) => {
    e?.preventDefault();
    setError('');
    setLoading(true);

    if (password !== confirmPassword) {
      setError("Mật khẩu không khớp!");
      setLoading(false);
      return;
    }

    try {
      console.log("🚀 Bắt đầu quy trình Zero-Knowledge Registration...");

      // --- BƯỚC 1: TẠO MASTER KEY (Client-side only) ---
      const salt = genRandomSalt(); 
      
      console.log("1. Đang tính toán Master Key từ mật khẩu...");
      const masterKey = await passwordToMasterKey(password, salt);
      // console.log(masterKey)

      // --- BƯỚC 2: TẠO AUTH HASH (Để đăng nhập) ---
      console.log("2. Đang tạo Auth Hash...");
      const authHash = await deriveAuthHash(masterKey);
      // console.log(authHash)

      // --- BƯỚC 3: TẠO CẶP KHÓA ĐỊNH DANH (Identity Keys) ---
      console.log("3. Đang sinh cặp khóa RSA/ElGamal...");
      const keyPair = await generateEG();

      // --- BƯỚC 4: XUẤT KHÓA (Export Keys) ---
      const publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.pub);
      const privateKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.sec);

      // --- BƯỚC 5: MÃ HÓA PRIVATE KEY (Két sắt) ---
      console.log("4. Đang đóng gói Private Key vào két sắt...");
      const privKeyJsonString = JSON.stringify(privateKeyJWK);
      const iv = genRandomSalt();
      
      const encryptedPrivateKeyCipher = await encryptWithGCM(
        masterKey, 
        privKeyJsonString, 
        iv
      );

      // --- BƯỚC 6: GỬI LÊN SERVER ---
      const payload = {
        email: email,
        auth_hash: authHash,
        salt: bufferToHex(salt),
        public_key: publicKeyJWK,
        encrypted_private_key: {
          iv: bufferToHex(iv),
          ciphertext: bufferToHex(encryptedPrivateKeyCipher)
        }
      };

      console.log("5. Gửi Payload lên API (Demo)");
      
      await axios.post('http://localhost:5000/api/auth/register', payload);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      alert("Đăng ký thành công! Hãy đăng nhập.");
      navigate('/login');

    } catch (err) {
      console.error("Lỗi đăng ký:", err);
      setError(err.response?.data?.message || "Đã có lỗi xảy ra khi xử lý mật mã.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.bgDecoration1}></div>
      <div style={styles.bgDecoration2}></div>
      
      <div style={styles.formContainer}>
        {/* Left side - Branding */}
        <div style={styles.brandingSide}>
          <div style={styles.brandingContent}>
            <div style={styles.logoContainer}>
              <Shield size={48} color="white" strokeWidth={2} />
            </div>
            <h1 style={styles.brandTitle}>TeamVault</h1>
            <p style={styles.brandSubtitle}>
              Hệ thống quản lý mật khẩu Zero-Knowledge
            </p>
            
            <div style={styles.featureList}>
              <div style={styles.featureItem}>
                <Check size={20} color="#10b981" />
                <span>Mã hóa End-to-End</span>
              </div>
              <div style={styles.featureItem}>
                <Check size={20} color="#10b981" />
                <span>Zero-Knowledge Architecture</span>
              </div>
              <div style={styles.featureItem}>
                <Check size={20} color="#10b981" />
                <span>Bảo mật tuyệt đối</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right side - Form */}
        <div style={styles.formSide}>
          <div style={styles.formContent}>
            <div style={styles.formHeader}>
              <h2 style={styles.formTitle}>Tạo Tài Khoản</h2>
              <p style={styles.formSubtitle}>
                Bắt đầu bảo vệ dữ liệu của bạn ngay hôm nay
              </p>
            </div>

            {error && (
              <div style={styles.errorAlert}>
                <div style={styles.errorIcon}>⚠️</div>
                <div>{error}</div>
              </div>
            )}

            <div style={styles.formWrapper}>
              {/* Email Input */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Email</label>
                <div style={styles.inputWrapper}>
                  <Mail size={20} style={styles.inputIcon} />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={styles.input}
                    placeholder="your.email@example.com"
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                  />
                </div>
              </div>

              {/* Password Input */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Mật khẩu</label>
                <div style={styles.inputWrapper}>
                  <Lock size={20} style={styles.inputIcon} />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={styles.input}
                    placeholder="Nhập mật khẩu mạnh"
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={styles.eyeButton}
                  >
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
                
                {password && (
                  <div style={styles.strengthContainer}>
                    <div style={styles.strengthBar}>
                      <div 
                        style={{
                          ...styles.strengthFill,
                          width: `${(passwordStrength.strength / 5) * 100}%`,
                          backgroundColor: passwordStrength.color
                        }}
                      ></div>
                    </div>
                    <span style={{...styles.strengthText, color: passwordStrength.color}}>
                      {passwordStrength.text}
                    </span>
                  </div>
                )}
              </div>

              {/* Confirm Password Input */}
              <div style={styles.inputGroup}>
                <label style={styles.label}>Nhập lại mật khẩu</label>
                <div style={styles.inputWrapper}>
                  <Lock size={20} style={styles.inputIcon} />
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    style={styles.input}
                    placeholder="Xác nhận mật khẩu"
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    style={styles.eyeButton}
                  >
                    {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
                {confirmPassword && password !== confirmPassword && (
                  <span style={styles.mismatchText}>Mật khẩu không khớp</span>
                )}
              </div>

              <button
                onClick={handleRegister}
                disabled={loading}
                style={{
                  ...styles.submitButton,
                  opacity: loading ? 0.7 : 1,
                  cursor: loading ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? (
                  <div style={styles.loadingContainer}>
                    <div style={styles.loadingSpinner}></div>
                    <span>Đang mã hóa & Đăng ký...</span>
                  </div>
                ) : (
                  'Đăng ký Tài khoản'
                )}
              </button>
            </div>

            <div style={styles.footer}>
              <p style={styles.footerText}>
                Đã có tài khoản?{' '}
                <a href="/login" style={styles.link}>
                  Đăng nhập ngay
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'stretch',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    padding: '0',
    position: 'relative',
    overflow: 'hidden'
  },
  bgDecoration1: {
    position: 'absolute',
    width: '500px',
    height: '500px',
    borderRadius: '50%',
    background: 'rgba(255, 255, 255, 0.1)',
    top: '-200px',
    left: '-200px',
    filter: 'blur(80px)'
  },
  bgDecoration2: {
    position: 'absolute',
    width: '400px',
    height: '400px',
    borderRadius: '50%',
    background: 'rgba(255, 255, 255, 0.1)',
    bottom: '-150px',
    right: '-150px',
    filter: 'blur(80px)'
  },
  formContainer: {
    display: 'flex',
    width: '100%',
    height: '100vh',
    backgroundColor: 'white',
    overflow: 'hidden',
    position: 'relative',
    zIndex: 1
  },
  brandingSide: {
    flex: '1',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    padding: '60px 40px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white'
  },
  brandingContent: {
    maxWidth: '350px'
  },
  logoContainer: {
    width: '80px',
    height: '80px',
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    borderRadius: '20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: '24px',
    backdropFilter: 'blur(10px)'
  },
  brandTitle: {
    fontSize: '36px',
    fontWeight: 'bold',
    marginBottom: '12px',
    margin: '0 0 12px 0'
  },
  brandSubtitle: {
    fontSize: '16px',
    opacity: 0.9,
    marginBottom: '40px',
    lineHeight: '1.6'
  },
  featureList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  featureItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    fontSize: '15px'
  },
  formSide: {
    flex: '1',
    padding: '60px 50px',
    display: 'flex',
    alignItems: 'center',
    backgroundColor: 'white',
    overflowY: 'auto'
  },
  formContent: {
    width: '100%',
    maxWidth: '400px',
    margin: '0 auto'
  },
  formHeader: {
    marginBottom: '32px'
  },
  formTitle: {
    fontSize: '28px',
    fontWeight: 'bold',
    color: '#1f2937',
    marginBottom: '8px',
    margin: '0 0 8px 0'
  },
  formSubtitle: {
    fontSize: '14px',
    color: '#6b7280'
  },
  errorAlert: {
    backgroundColor: '#fee2e2',
    border: '1px solid #fecaca',
    borderRadius: '8px',
    padding: '12px 16px',
    marginBottom: '24px',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    color: '#991b1b',
    fontSize: '14px'
  },
  errorIcon: {
    fontSize: '18px'
  },
  formWrapper: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px'
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  label: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#374151'
  },
  inputWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  inputIcon: {
    position: 'absolute',
    left: '14px',
    color: '#9ca3af',
    pointerEvents: 'none'
  },
  input: {
    width: '100%',
    padding: '12px 12px 12px 44px',
    border: '2px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '15px',
    transition: 'all 0.2s',
    outline: 'none',
    boxSizing: 'border-box'
  },
  eyeButton: {
    position: 'absolute',
    right: '12px',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    color: '#9ca3af',
    padding: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'color 0.2s'
  },
  strengthContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginTop: '4px'
  },
  strengthBar: {
    flex: 1,
    height: '4px',
    backgroundColor: '#e5e7eb',
    borderRadius: '2px',
    overflow: 'hidden'
  },
  strengthFill: {
    height: '100%',
    transition: 'all 0.3s',
    borderRadius: '2px'
  },
  strengthText: {
    fontSize: '12px',
    fontWeight: '600',
    minWidth: '80px',
    textAlign: 'right'
  },
  mismatchText: {
    fontSize: '12px',
    color: '#ef4444',
    marginTop: '4px'
  },
  submitButton: {
    width: '100%',
    padding: '14px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.3s',
    marginTop: '8px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '48px'
  },
  loadingContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px'
  },
  loadingSpinner: {
    width: '20px',
    height: '20px',
    border: '3px solid rgba(255, 255, 255, 0.3)',
    borderTop: '3px solid white',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite'
  },
  footer: {
    marginTop: '24px',
    textAlign: 'center'
  },
  footerText: {
    fontSize: '14px',
    color: '#6b7280'
  },
  link: {
    color: '#667eea',
    textDecoration: 'none',
    fontWeight: '600',
    transition: 'color 0.2s'
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
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
  }
  
  a:hover {
    color: #764ba2 !important;
  }
  
  @media (max-width: 768px) {
    .formContainer {
      flex-direction: column;
    }
  }
`;
document.head.appendChild(styleSheet);

export default Register;