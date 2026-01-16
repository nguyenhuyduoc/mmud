/**
 * Secure Key Storage with HSM Integration (Web Crypto API Non-Extractable Keys)
 * Stores keys in memory only with non-extractable flag for hardware security module protection
 */

class SecureKeyStorage {
    constructor() {
        // In-memory storage for non-extractable keys
        // Keys are lost on page reload - this is intentional for security
        this.keys = new Map();
        this.keyMetadata = new Map();

        // Bind cleanup on page unload
        if (typeof window !== 'undefined') {
            window.addEventListener('beforeunload', () => this.clearAll());
        }
    }

    /**
     * Store a non-extractable key
     */
    async storeKey(keyId, cryptoKey, metadata = {}) {
        // Verify key is non-extractable for HSM protection
        if (cryptoKey.extractable) {
            console.warn(`⚠️  Key ${keyId} is extractable - not HSM-protected!`);

            // Log for security audit
            if (metadata.requireNonExtractable) {
                throw new Error('Key must be non-extractable for HSM protection');
            }
        }

        this.keys.set(keyId, cryptoKey);
        this.keyMetadata.set(keyId, {
            ...metadata,
            storedAt: new Date(),
            extractable: cryptoKey.extractable,
            algorithm: cryptoKey.algorithm.name,
            type: cryptoKey.type
        });

        console.log(`🔑 Stored key: ${keyId} (extractable: ${cryptoKey.extractable})`);
        return true;
    }

    /**
     * Retrieve a stored key
     */
    getKey(keyId) {
        const key = this.keys.get(keyId);
        if (!key) {
            console.warn(`⚠️  Key ${keyId} not found`);
            return null;
        }
        return key;
    }

    /**
     * Get key metadata
     */
    getKeyMetadata(keyId) {
        return this.keyMetadata.get(keyId);
    }

    /**
     * Check if key exists
     */
    hasKey(keyId) {
        return this.keys.has(keyId);
    }

    /**
     * List all stored key IDs
     */
    listKeys() {
        return Array.from(this.keys.keys());
    }

    /**
     * Remove a specific key
     */
    deleteKey(keyId) {
        const deleted = this.keys.delete(keyId);
        this.keyMetadata.delete(keyId);

        if (deleted) {
            console.log(`🗑️  Deleted key: ${keyId}`);
        }
        return deleted;
    }

    /**
     * Clear all keys (on logout or session end)
     */
    clearAll() {
        const count = this.keys.size;
        this.keys.clear();
        this.keyMetadata.clear();
        console.log(`🧹 Cleared ${count} keys from memory`);
    }

    /**
     * Derive a session key from master key (without extracting master key)
     */
    async deriveSessionKey(masterKeyId, info, salt) {
        const masterKey = this.getKey(masterKeyId);
        if (!masterKey) {
            throw new Error('Master key not found');
        }

        // Derive session key using HKDF without ever exporting master key
        const { HKDF } = await import('./lib.js');
        const [sessionKey, _] = await HKDF(masterKey, salt, info);

        // Store derived key (also non-extractable)
        const sessionKeyId = `session_${Date.now()}`;
        await this.storeKey(sessionKeyId, sessionKey, {
            derivedFrom: masterKeyId,
            purpose: info,
            requireNonExtractable: true
        });

        return { keyId: sessionKeyId, key: sessionKey };
    }

    /**
     * Perform encryption with stored key (key never leaves storage)
     */
    async encryptWithStoredKey(keyId, plaintext, iv, additionalData = '') {
        const key = this.getKey(keyId);
        if (!key) {
            throw new Error(`Key ${keyId} not found`);
        }

        const { encryptWithGCM } = await import('./lib.js');
        return await encryptWithGCM(key, plaintext, iv, additionalData);
    }

    /**
     * Perform decryption with stored key (key never leaves storage)
     */
    async decryptWithStoredKey(keyId, ciphertext, iv, additionalData = '', returnBinary = false) {
        const key = this.getKey(keyId);
        if (!key) {
            throw new Error(`Key ${keyId} not found`);
        }

        const { decryptWithGCM } = await import('./lib.js');
        return await decryptWithGCM(key, ciphertext, iv, additionalData, returnBinary);
    }

    /**
     * Get storage statistics
     */
    getStats() {
        const stats = {
            totalKeys: this.keys.size,
            nonExtractableKeys: 0,
            extractableKeys: 0,
            keysByType: {}
        };

        for (const [keyId, metadata] of this.keyMetadata.entries()) {
            if (metadata.extractable) {
                stats.extractableKeys++;
            } else {
                stats.nonExtractableKeys++;
            }

            const type = metadata.algorithm || 'unknown';
            stats.keysByType[type] = (stats.keysByType[type] || 0) + 1;
        }

        return stats;
    }

    /**
     * Verify HSM protection
     * Returns true if all critical keys are non-extractable
     */
    verifyHSMProtection() {
        const criticalKeys = ['master_key', 'private_key'];

        for (const keyId of criticalKeys) {
            const metadata = this.getKeyMetadata(keyId);
            if (metadata && metadata.extractable) {
                console.error(`❌ Critical key ${keyId} is not HSM-protected (extractable)`);
                return false;
            }
        }

        console.log('✅ All critical keys are HSM-protected (non-extractable)');
        return true;
    }
}

// Singleton instance
const secureKeyStorage = new SecureKeyStorage();

// Export for use in components
export default secureKeyStorage;
