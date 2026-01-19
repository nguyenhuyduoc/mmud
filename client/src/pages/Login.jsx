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
      console.log(" Bắt đầu quy trình Zero-Knowledge Login...");

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

      console.log(" Đã giải mã thành công Private Key!");

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

      // Handle rate limiting errors
      if (err.response?.status === 429) {
        const { retryAfter, lockedUntil } = err.response.data;
        const waitTime = retryAfter || Math.ceil((new Date(lockedUntil) - new Date()) / 1000);
        setError(`Too many login attempts. Please wait ${waitTime} seconds and try again.`);
      }
      // Handle decryption failures (wrong password)
      else if (err.name === 'OperationError') {
        setError("Mật khẩu sai (Giải mã thất bại)!");
      }
      // Handle other errors
      else {
        setError(err.response?.data?.message || "Đăng nhập thất bại");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.wrapper}>
        {/* Left side - Welcome Banner */}
        <div style={styles.leftSide}>
          <div style={styles.decorativeShapes}>
            <div style={styles.shape1}></div>
            <div style={styles.shape2}></div>
            <div style={styles.shape3}></div>
            <div style={styles.shape4}></div>
            <div style={styles.shape5}></div>
          </div>
          <div style={styles.welcomeContent}>
            <h1 style={styles.welcomeTitle}>Welcome to TeamVault</h1>
            <p style={styles.welcomeText}>
              Zero-Knowledge Password Manager
              <br />
              Bảo vệ dữ liệu của bạn với công nghệ mã hóa End-to-End
              <br />
              Chỉ bạn mới có thể truy cập thông tin của mình
            </p>
          </div>
        </div>

        {/* Right side - Login Form */}
        <div style={styles.rightSide}>
          <div style={styles.formBox}>
            <div style={styles.formHeader}>
              <h2 style={styles.formTitle}>USER LOGIN</h2>
            </div>

            {error && (
              <div style={styles.errorAlert}>
                {error}
              </div>
            )}

            <div style={styles.form}>
              {/* Email Input */}
              <div style={styles.inputGroup}>
                <div style={styles.inputWrapper}>
                  <Mail size={20} style={styles.inputIcon} />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={styles.input}
                    placeholder="Email"
                    onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                  />
                </div>
              </div>

              {/* Password Input */}
              <div style={styles.inputGroup}>
                <div style={styles.inputWrapper}>
                  <Lock size={20} style={styles.inputIcon} />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={styles.input}
                    placeholder="Password"
                    onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={styles.eyeButton}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              <div style={styles.rememberRow}>
                <label style={styles.rememberLabel}>
                  <input type="checkbox" style={styles.checkbox} />
                  <span>Remember me</span>
                </label>
                <a href="#" style={styles.forgotLink}>Forgot password?</a>
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
                  <div style={styles.loadingSpinner}></div>
                ) : (
                  'LOGIN'
                )}
              </button>

              <div style={styles.signupLink}>
                Don't have an account? <a href="/register" style={styles.link}>Sign up</a>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={styles.footer}>
        designed by <span style={styles.footerBrand}>TeamVault</span>
      </div>
    </div>
  );
};

const styles = {
  container: {
    height: '100vh',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '0',
    position: 'relative',
    overflow: 'hidden'
  },
  wrapper: {
    display: 'flex',
    width: '100%',
    height: '100%',
    backgroundColor: 'white',
    borderRadius: '0',
    overflow: 'hidden',
    boxShadow: 'none'
  },
  leftSide: {
    flex: 1,
    background: 'linear-gradient(135deg, #667eea 0%, #f093fb 100%)',
    padding: '0',
    position: 'relative',
    overflow: 'hidden',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  decorativeShapes: {
    position: 'absolute',
    width: '100%',
    height: '100%',
    top: 0,
    left: 0,
    overflow: 'hidden'
  },
  shape1: {
    position: 'absolute',
    width: '150px',
    height: '40px',
    background: 'linear-gradient(45deg, rgba(255, 107, 107, 0.6), rgba(255, 159, 64, 0.6))',
    borderRadius: '20px',
    transform: 'rotate(-45deg)',
    top: '80px',
    left: '60px'
  },
  shape2: {
    position: 'absolute',
    width: '100px',
    height: '30px',
    background: 'linear-gradient(45deg, rgba(255, 159, 64, 0.5), rgba(255, 107, 107, 0.5))',
    borderRadius: '15px',
    transform: 'rotate(-30deg)',
    top: '150px',
    left: '100px'
  },
  shape3: {
    position: 'absolute',
    width: '80px',
    height: '25px',
    background: 'linear-gradient(45deg, rgba(255, 107, 107, 0.4), rgba(255, 159, 64, 0.4))',
    borderRadius: '12px',
    transform: 'rotate(-55deg)',
    top: '200px',
    left: '50px'
  },
  shape4: {
    position: 'absolute',
    width: '120px',
    height: '35px',
    background: 'linear-gradient(45deg, rgba(255, 159, 64, 0.6), rgba(255, 107, 107, 0.6))',
    borderRadius: '18px',
    transform: 'rotate(-40deg)',
    bottom: '120px',
    right: '80px'
  },
  shape5: {
    position: 'absolute',
    width: '90px',
    height: '28px',
    background: 'linear-gradient(45deg, rgba(255, 107, 107, 0.5), rgba(255, 159, 64, 0.5))',
    borderRadius: '14px',
    transform: 'rotate(-50deg)',
    bottom: '180px',
    right: '120px'
  },
  welcomeContent: {
    position: 'relative',
    zIndex: 1,
    color: 'white',
    textAlign: 'left'
  },
  welcomeTitle: {
    fontSize: '38px',
    fontWeight: 'bold',
    marginBottom: '20px',
    margin: '0 0 20px 0',
    lineHeight: '1.2'
  },
  welcomeText: {
    fontSize: '15px',
    lineHeight: '1.8',
    opacity: 0.95,
    margin: 0
  },
  rightSide: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '0',
    backgroundColor: '#fafafa'
  },
  formBox: {
    width: '100%',
    maxWidth: '340px'
  },
  formHeader: {
    marginBottom: '30px',
    textAlign: 'center'
  },
  formTitle: {
    fontSize: '20px',
    fontWeight: '600',
    color: '#667eea',
    margin: 0,
    letterSpacing: '1px'
  },
  errorAlert: {
    backgroundColor: '#fee2e2',
    border: '1px solid #fecaca',
    borderRadius: '8px',
    padding: '12px',
    marginBottom: '20px',
    color: '#991b1b',
    fontSize: '14px',
    textAlign: 'center'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column'
  },
  inputWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  inputIcon: {
    position: 'absolute',
    left: '12px',
    color: '#9ca3af',
    pointerEvents: 'none'
  },
  input: {
    width: '100%',
    padding: '12px 12px 12px 40px',
    border: '1px solid #e5e7eb',
    borderRadius: '8px',
    fontSize: '14px',
    transition: 'all 0.2s',
    outline: 'none',
    backgroundColor: 'white',
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
    justifyContent: 'center'
  },
  rememberRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '13px',
    marginTop: '4px'
  },
  rememberLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    cursor: 'pointer',
    color: '#6b7280'
  },
  checkbox: {
    cursor: 'pointer'
  },
  forgotLink: {
    color: '#667eea',
    textDecoration: 'none',
    fontSize: '13px',
    fontWeight: '500'
  },
  submitButton: {
    width: '100%',
    padding: '14px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    border: 'none',
    borderRadius: '25px',
    fontSize: '14px',
    fontWeight: '600',
    cursor: 'pointer',
    marginTop: '8px',
    letterSpacing: '1px',
    boxShadow: '0 4px 15px rgba(102, 126, 234, 0.4)',
    transition: 'all 0.3s',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '48px'
  },
  loadingSpinner: {
    width: '20px',
    height: '20px',
    border: '3px solid rgba(255, 255, 255, 0.3)',
    borderTop: '3px solid white',
    borderRadius: '50%',
    animation: 'spin 0.8s linear infinite'
  },
  signupLink: {
    textAlign: 'center',
    fontSize: '13px',
    color: '#6b7280',
    marginTop: '8px'
  },
  link: {
    color: '#667eea',
    textDecoration: 'none',
    fontWeight: '600'
  },
  footer: {
    position: 'absolute',
    bottom: '20px',
    fontSize: '13px',
    color: 'white',
    opacity: 0.9
  },
  footerBrand: {
    fontWeight: '600'
  }
};

export default Login;
