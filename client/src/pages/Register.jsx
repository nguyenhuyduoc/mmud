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

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError("Email không hợp lệ! Vui lòng nhập đúng định dạng (vd: user@example.com)");
      setLoading(false);
      return;
    }

    // Check password match
    if (password !== confirmPassword) {
      setError("Mật khẩu không khớp!");
      setLoading(false);
      return;
    }

    // Password strength check
    if (password.length < 8) {
      setError("Mật khẩu phải có ít nhất 8 ký tự!");
      setLoading(false);
      return;
    }

    try {
      console.log(" Bắt đầu quy trình Zero-Knowledge Registration...");

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
              Tạo tài khoản để bắt đầu bảo vệ dữ liệu của bạn
              <br />
              Hoàn toàn miễn phí và bảo mật tuyệt đối
            </p>
          </div>
        </div>

        {/* Right side - Register Form */}
        <div style={styles.rightSide}>
          <div style={styles.formBox}>
            <div style={styles.formHeader}>
              <h2 style={styles.formTitle}>CREATE ACCOUNT</h2>
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
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
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
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={styles.eyeButton}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
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
                    <span style={{ ...styles.strengthText, color: passwordStrength.color }}>
                      {passwordStrength.text}
                    </span>
                  </div>
                )}
              </div>

              {/* Confirm Password Input */}
              <div style={styles.inputGroup}>
                <div style={styles.inputWrapper}>
                  <Lock size={20} style={styles.inputIcon} />
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    style={styles.input}
                    placeholder="Confirm Password"
                    onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    style={styles.eyeButton}
                  >
                    {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
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
                  <div style={styles.loadingSpinner}></div>
                ) : (
                  'SIGN UP'
                )}
              </button>

              <div style={styles.signupLink}>
                Already have an account? <a href="/login" style={styles.link}>Login</a>
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
    flexDirection: 'column',
    gap: '6px'
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
  strengthContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px'
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
    fontSize: '11px',
    fontWeight: '600',
    minWidth: '70px',
    textAlign: 'right'
  },
  mismatchText: {
    fontSize: '11px',
    color: '#ef4444'
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

export default Register;
