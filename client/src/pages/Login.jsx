// import { useState } from 'react';
// import axios from 'axios';
// import { useNavigate, Link } from 'react-router-dom';
// import { 
//   passwordToMasterKey, 
//   deriveAuthHash, 
//   decryptWithGCM,
//   hexToBuffer 
// } from '../utils/lib';


// const Login = () => {
//   const [email, setEmail] = useState('');
//   const [password, setPassword] = useState('');
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState('');
  
//   const navigate = useNavigate();

//   const handleLogin = async (e) => {
//     e.preventDefault();
//     setLoading(true);
//     setError('');

//     try {
//       console.log("🚀 Bắt đầu quy trình Zero-Knowledge Login...");

//       // --- BƯỚC 1: LẤY SALT TỪ SERVER ---
//       // Server không biết pass, nhưng biết salt của user này
//       console.log("1. Đang xin Salt từ Server...");
//       const saltRes = await axios.get(`http://localhost:5000/api/auth/salt/${email}`);
//       const salt = saltRes.data.salt;
//       console.log( salt)
//       // --- BƯỚC 2: TÁI TẠO MASTER KEY ---
//       console.log("2. Đang tính lại Master Key từ Mật khẩu + Salt...");
//       // Bước này tốn tài nguyên CPU nhất (PBKDF2)
//       const masterKey = await passwordToMasterKey(password, salt);
//       console.log(masterKey)
//       // --- BƯỚC 3: TẠO AUTH HASH ---
//       console.log("3. Đang tạo Auth Hash để gửi đi...");
//       const authHash = await deriveAuthHash(masterKey);
//       console.log(authHash)
//       // --- BƯỚC 4: GỬI REQUEST LOGIN ---
//       console.log("4. Gửi Auth Hash lên Server...");
//       const loginRes = await axios.post('http://localhost:5000/api/auth/login', {
//         email: email,
//         auth_hash: authHash
//       });

//       // --- BƯỚC 5: GIẢI MÃ KÉT SẮT (QUAN TRỌNG NHẤT) ---
//       console.log("5. Đăng nhập thành công! Đang giải mã Private Key...");
      
//       const { encrypted_private_key, public_key } = loginRes.data;

//       // Dùng Master Key đang có trong RAM để mở két sắt
//       const privateKeyJson = await decryptWithGCM(
//         masterKey, 
//         hexToBuffer(encrypted_private_key.ciphertext), 
//         hexToBuffer(encrypted_private_key.iv)
//       );

//       console.log("✅ Đã giải mã thành công Private Key!");

//       // --- BƯỚC 6: LƯU TRỮ TẠM THỜI (SESSION) ---
//       // Lưu vào SessionStorage để dùng ở trang Dashboard
//       // Lưu ý: Trong thực tế nên dùng Context API hoặc Redux để lưu trong RAM (an toàn hơn)
//       // Nhưng để demo reload không mất dữ liệu, ta dùng SessionStorage tạm.
//       sessionStorage.setItem('user_email', email);
//       sessionStorage.setItem('user_public_key', JSON.stringify(public_key));
//       sessionStorage.setItem('user_private_key', privateKeyJson); // Đã giải mã
      
//       // Chuyển hướng vào trong
//       navigate('/dashboard');

//     } catch (err) {
//       console.error("Lỗi đăng nhập:", err);
//       // Nếu giải mã thất bại (do sai pass nhưng auth_hash vô tình trùng - hiếm)
//       if (err.name === 'OperationError') {
//          setError("Mật khẩu sai (Giải mã thất bại)!");
//       } else {
//          setError(err.response?.data?.message || "Đăng nhập thất bại");
//       }
//     } finally {
//       setLoading(false);
//     }
//   };

//   return (
//     <div style={styles.container}>
//       <div style={styles.formBox}>
//         <h2>Đăng nhập</h2>
//         <p style={{marginBottom: '20px', color: '#666'}}>Mở khóa Két sắt của bạn</p>
        
//         {error && <div style={styles.error}>{error}</div>}
        
//         <form onSubmit={handleLogin}>
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
//             />
//           </div>

//           <button type="submit" disabled={loading} style={styles.button}>
//             {loading ? 'Đang giải mã...' : 'Mở khóa & Đăng nhập'}
//           </button>
//         </form>
        
//         <p style={{marginTop: '15px'}}>
//           Chưa có tài khoản? <Link to="/register">Đăng ký ngay</Link>
//         </p>
//       </div>
//     </div>
//   );
// };

// const styles = {
//   container: { display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', backgroundColor: '#e9ecef' },
//   formBox: { padding: '30px', borderRadius: '8px', backgroundColor: 'white', boxShadow: '0 4px 12px rgba(0,0,0,0.1)', width: '400px' },
//   inputGroup: { marginBottom: '15px' },
//   input: { width: '100%', padding: '10px', marginTop: '5px', border: '1px solid #ddd', borderRadius: '4px', boxSizing: 'border-box' },
//   button: { width: '100%', padding: '12px', backgroundColor: '#28a745', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '16px' },
//   error: { backgroundColor: '#ffebee', color: '#c62828', padding: '10px', borderRadius: '4px', marginBottom: '15px' }
// };

// export default Login;

import { useState } from 'react';
import { Lock, Mail, Eye, EyeOff, Shield, ArrowRight, Unlock } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios'
// Import các hàm crypto từ utils/lib của bạn
import { 
  passwordToMasterKey, 
  deriveAuthHash, 
  decryptWithGCM,
  hexToBuffer 
} from '../utils/lib';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
 const navigate = useNavigate();
  const handleLogin = async (e) => {
    e?.preventDefault();
    setLoading(true);
    setError('');

    try {
      console.log("🚀 Bắt đầu quy trình Zero-Knowledge Login...");

      // --- BƯỚC 1: LẤY SALT TỪ SERVER ---
      console.log("1. Đang xin Salt từ Server...");
      const saltRes = await axios.get(`http://localhost:5000/api/auth/salt/${email}`);
      const salt = saltRes.data.salt;
      // console.log(salt)

      // --- BƯỚC 2: TÁI TẠO MASTER KEY ---
      console.log("2. Đang tính lại Master Key từ Mật khẩu + Salt...");
      const masterKey = await passwordToMasterKey(password, salt);
      // console.log(masterKey)

      // --- BƯỚC 3: TẠO AUTH HASH ---
      console.log("3. Đang tạo Auth Hash để gửi đi...");
      const authHash = await deriveAuthHash(masterKey);
      // console.log(authHash)

      // --- BƯỚC 4: GỬI REQUEST LOGIN ---
      console.log("4. Gửi Auth Hash lên Server...");
      const loginRes = await axios.post('http://localhost:5000/api/auth/login', {
        email: email,
        auth_hash: authHash
      });

      // --- BƯỚC 5: GIẢI MÃ KÉT SẮT (QUAN TRỌNG NHẤT) ---
      console.log("5. Đăng nhập thành công! Đang giải mã Private Key...");
      
      const { encrypted_private_key, public_key } = loginRes.data;

      // Dùng Master Key đang có trong RAM để mở két sắt
      const privateKeyJson = await decryptWithGCM(
        masterKey, 
        hexToBuffer(encrypted_private_key.ciphertext), 
        hexToBuffer(encrypted_private_key.iv)
      );

      console.log("✅ Đã giải mã thành công Private Key!");

      // --- BƯỚC 6: LƯU TRỮ TẠM THỜI (SESSION) ---
      sessionStorage.setItem('user_email', email);
      sessionStorage.setItem('user_public_key', JSON.stringify(public_key));
      sessionStorage.setItem('user_private_key', privateKeyJson);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      alert("Đăng nhập thành công! (Demo)");
      navigate('/dashboard');

    } catch (err) {
      console.error("Lỗi đăng nhập:", err);
      if (err.name === 'OperationError') {
         setError("Mật khẩu sai (Giải mã thất bại)!");
      } else {
         setError(err.response?.data?.message || "Đăng nhập thất bại");
      }
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
            <h1 style={styles.brandTitle}>Chào mừng trở lại!</h1>
            <p style={styles.brandSubtitle}>
              Đăng nhập để truy cập vào két sắt bảo mật của bạn
            </p>
            
            <div style={styles.securityBadge}>
              <Unlock size={24} color="#10b981" />
              <div>
                <div style={styles.badgeTitle}>Zero-Knowledge Security</div>
                <div style={styles.badgeText}>
                  Chỉ bạn mới có thể giải mã dữ liệu của mình
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right side - Login Form */}
        <div style={styles.formSide}>
          <div style={styles.formContent}>
            <div style={styles.formHeader}>
              <h2 style={styles.formTitle}>Đăng nhập</h2>
              <p style={styles.formSubtitle}>
                Nhập thông tin để mở khóa két sắt
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
                    onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                  />
                </div>
              </div>

              {/* Password Input */}
              <div style={styles.inputGroup}>
                <div style={styles.labelRow}>
                  <label style={styles.label}>Mật khẩu</label>
                  <a href="#" style={styles.forgotLink}>Quên mật khẩu?</a>
                </div>
                <div style={styles.inputWrapper}>
                  <Lock size={20} style={styles.inputIcon} />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={styles.input}
                    placeholder="Nhập mật khẩu"
                    onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={styles.eyeButton}
                  >
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
              </div>

              <button
                onClick={handleLogin}
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
                    <span>Đang giải mã...</span>
                  </div>
                ) : (
                  <div style={styles.buttonContent}>
                    <span>Mở khóa & Đăng nhập</span>
                    <ArrowRight size={20} />
                  </div>
                )}
              </button>
            </div>

            <div style={styles.divider}>
              <span style={styles.dividerText}>hoặc</span>
            </div>

            <div style={styles.footer}>
              <p style={styles.footerText}>
                Chưa có tài khoản?{' '}
                <a href="/register" style={styles.link}>
                  Đăng ký ngay
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
    maxWidth: '400px'
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
    marginBottom: '48px',
    lineHeight: '1.6'
  },
  securityBadge: {
    backgroundColor: 'rgba(255, 255, 255, 0.15)',
    backdropFilter: 'blur(10px)',
    borderRadius: '16px',
    padding: '20px',
    display: 'flex',
    gap: '16px',
    alignItems: 'flex-start',
    border: '1px solid rgba(255, 255, 255, 0.2)'
  },
  badgeTitle: {
    fontSize: '16px',
    fontWeight: '600',
    marginBottom: '6px'
  },
  badgeText: {
    fontSize: '14px',
    opacity: 0.85,
    lineHeight: '1.5'
  },
  formSide: {
    flex: '1',
    padding: '60px 50px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'white'
  },
  formContent: {
    width: '100%',
    maxWidth: '400px'
  },
  formHeader: {
    marginBottom: '32px'
  },
  formTitle: {
    fontSize: '32px',
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
  labelRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  label: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#374151'
  },
  forgotLink: {
    fontSize: '13px',
    color: '#667eea',
    textDecoration: 'none',
    fontWeight: '500',
    transition: 'color 0.2s'
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
  buttonContent: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px'
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
  divider: {
    position: 'relative',
    textAlign: 'center',
    margin: '24px 0',
    '::before': {
      content: '""',
      position: 'absolute',
      top: '50%',
      left: 0,
      right: 0,
      height: '1px',
      backgroundColor: '#e5e7eb'
    }
  },
  dividerText: {
    backgroundColor: 'white',
    padding: '0 12px',
    fontSize: '13px',
    color: '#9ca3af',
    position: 'relative',
    zIndex: 1
  },
  footer: {
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

export default Login;