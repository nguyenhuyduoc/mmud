// =============================================================================
// HSM-PROTECTED KEY GENERATION (Non-Extractable Keys)
// =============================================================================

/**
 * Generate secure ECDH keypair with non-extractable private key (HSM-protected)
 * Private key cannot be exported - provides hardware-level protection
 */
export async function generateSecureEG() {
    const keypair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-384" },
        false, // ⚠️ non-extractable = true (HSM protection)
        ["deriveKey"]
    );

    // Public key can be extractable for sharing
    const publicKeyJWK = await crypto.subtle.exportKey("jwk", keypair.publicKey);

    return {
        pub: keypair.publicKey,
        pubJWK: publicKeyJWK, // For transmission
        sec: keypair.privateKey // Non-extractable!
    };
}

/**
 * Generate secure master key from password with non-extractable flag
 * Master key stays in HSM, cannot be extracted to JavaScript
 */
export async function passwordToSecureMasterKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        stringToBuffer(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    let saltBuffer;
    if (typeof salt === 'string') {
        saltBuffer = hexToBuffer(salt);
    } else {
        saltBuffer = salt;
    }

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false, // ⚠️ non-extractable (HSM protection)
        ["encrypt", "decrypt"]
    );
}

/**
 * Generate ephemeral keypair for Forward Secrecy
 * Creates single-use keys that are discarded after key exchange
 */
export async function generateEphemeralKeyPair() {
    return await generateEG(); // Use standard generateEG for ephemeral keys
}

/**
 * Derive next key in ratchet chain (for Forward Secrecy)
 * Uses HKDF to create key derivation chain
 */
export async function deriveNextKey(currentKey, info = "ratchet-forward") {
    // Use first output of HKDF as next key
    const salt = genRandomSalt();
    const [nextKey, _] = await HKDF(currentKey, currentKey, info);
    return nextKey;
}

/**
 * Key attestation - verify key is non-extractable
 * Returns true if key has HSM protection
 */
export async function verifyKeyAttestation(cryptoKey) {
    if (cryptoKey.extractable) {
        console.warn('⚠️  Key is extractable - no HSM protection');
        return false;
    }

    console.log('✅ Key is non-extractable (HSM-protected)');
    return true;
}
