/* eslint-disable no-undef */
// "use strict";

// --- CÔNG CỤ CHUYỂN ĐỔI (THAY THẾ BUFFER) ---
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Helper: Thay thế Buffer.from(str)
function stringToBuffer(str) {
  return encoder.encode(str);
}

// Helper: Thay thế buffer.toString()
export function bufferToString(arr) {
  return decoder.decode(arr);
}

export function hexToBuffer(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Helper: Chuyển ArrayBuffer sang Hex String (để hiển thị hoặc debug)
export function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export const govEncryptionDataStr = "AES-GENERATION";

export function genRandomSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len));
}

export async function cryptoKeyToJSON(cryptoKey) {
  const key = await crypto.subtle.exportKey("jwk", cryptoKey);
  return key;
}

export async function generateEG() {
  const keypair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-384" },
    true,
    ["deriveKey"]
  );
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

export async function computeDH(myPrivateKey, theirPublicKey) {
  return await crypto.subtle.deriveKey(
    { name: "ECDH", public: theirPublicKey },
    myPrivateKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"]
  );
}

export async function verifyWithECDSA(publicKey, message, signature) {
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    publicKey,
    signature,
    stringToBuffer(message)
  );
}

export async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  const hmacBuf = await crypto.subtle.sign(
    { name: "HMAC" },
    key,
    stringToBuffer(data)
  );
  const out = await crypto.subtle.importKey(
    "raw",
    hmacBuf,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
  if (exportToArrayBuffer) {
    return await crypto.subtle.exportKey("raw", out);
  }
  return out;
}

export async function HMACtoHMACKey(key, data) {
  const hmacBuf = await crypto.subtle.sign(
    { name: "HMAC" },
    key,
    stringToBuffer(data)
  );
  return await crypto.subtle.importKey(
    "raw",
    hmacBuf,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
}

export async function HKDF(inputKey, salt, infoStr) {
  const inputKeyBuf = await crypto.subtle.sign(
    { name: "HMAC" },
    inputKey,
    stringToBuffer("0")
  );
  const inputKeyHKDF = await crypto.subtle.importKey(
    "raw",
    inputKeyBuf,
    "HKDF",
    false,
    ["deriveKey"]
  );

  const salt1 = await crypto.subtle.sign(
    { name: "HMAC" },
    salt,
    stringToBuffer("salt1")
  );
  const salt2 = await crypto.subtle.sign(
    { name: "HMAC" },
    salt,
    stringToBuffer("salt2")
  );

  const hkdfOut1 = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt1,
      info: stringToBuffer(infoStr),
    },
    inputKeyHKDF,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );

  const hkdfOut2 = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt2,
      info: stringToBuffer(infoStr),
    },
    inputKeyHKDF,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );

  return [hkdfOut1, hkdfOut2];
}

export async function encryptWithGCM(key, plaintext, iv, authenticatedData = "") {
  // Tự động chuyển đổi nếu plaintext là string
  const dataBuffer = typeof plaintext === 'string' ? stringToBuffer(plaintext) : plaintext;
  
  return await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      additionalData: stringToBuffer(authenticatedData),
    },
    key,
    dataBuffer
  );
}

export async function decryptWithGCM(key, ciphertext, iv, authenticatedData = "", returnBinary = false) {
  // Giải mã ra ArrayBuffer
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv instanceof Array || iv instanceof Uint8Array ? new Uint8Array(iv) : iv, 
      additionalData: stringToBuffer(authenticatedData),
    },
    key,
    ciphertext
  );

  // --- SỬA ĐOẠN NÀY ---
  // Nếu tham số returnBinary = true, trả về Raw Buffer (Dùng cho Key Wrapping)
  if (returnBinary) {
    return decryptedBuffer;
  }
  // Mặc định trả về String (Dùng cho Login/View Content)
  return bufferToString(decryptedBuffer);
}
// --- ECDSA ---

export async function generateECDSA() {
  const keypair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"]
  );
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

export async function signWithECDSA(privateKey, message) {
  return await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    privateKey,
    stringToBuffer(message)
  );
}

// --- CÁC HÀM MỚI CHO TEAMVAULT ---

// 1. Password -> Master Key (PBKDF2)
export async function passwordToMasterKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    stringToBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  // --- SỬA ĐOẠN NÀY ---
  let saltBuffer;
  if (typeof salt === 'string') {
    // Nếu là string (từ Server về), nó là Hex -> Dùng hexToBuffer để khôi phục byte gốc
    saltBuffer = hexToBuffer(salt);
  } else {
    // Nếu là Uint8Array (lúc Register), dùng luôn
    saltBuffer = salt;
  }
  // --------------------

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// 2. Master Key -> Auth Hash (SHA-256)
export async function deriveAuthHash(masterKey) {
  const rawKey = await crypto.subtle.exportKey("raw", masterKey);
  const hashBuffer = await crypto.subtle.digest("SHA-256", rawKey);
  return bufferToHex(hashBuffer);
}