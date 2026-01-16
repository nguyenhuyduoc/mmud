/**
 * Certificate Verification Utilities for Client
 * Handles CA certificate verification on browser side
 */

import { verifyWithECDSA, cryptoKeyToJSON } from './lib';
import axios from 'axios';

class CertificateVerifier {
    constructor() {
        this.caPublicKey = null;
        this.certificateCache = new Map();
    }

    /**
     * Initialize: Fetch and store CA public key
     */
    async initialize() {
        if (this.caPublicKey) return; // Already initialized

        try {
            const response = await axios.get('http://localhost:5000/api/ca/public-key');
            const caPublicKeyJWK = response.data.ca_public_key;

            // Import CA public key for verification
            this.caPublicKey = await crypto.subtle.importKey(
                'jwk',
                caPublicKeyJWK,
                { name: 'ECDSA', namedCurve: 'P-384' },
                true,
                ['verify']
            );

            console.log('✅ CA public key loaded');
            return true;
        } catch (error) {
            console.error('Failed to load CA public key:', error);
            return false;
        }
    }

    /**
     * Verify a certificate signature
     */
    async verifyCertificate(certificate, signature) {
        await this.initialize();

        if (!this.caPublicKey) {
            throw new Error('CA public key not initialized');
        }

        try {
            const certString = JSON.stringify(certificate);
            const signatureBuffer = new Uint8Array(
                signature.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );

            const isValid = await verifyWithECDSA(
                this.caPublicKey,
                certString,
                signatureBuffer
            );

            if (!isValid) {
                console.error('❌ Invalid certificate signature');
                return false;
            }

            // Check expiration
            const expiresAt = new Date(certificate.expires_at);
            if (expiresAt < new Date()) {
                console.error('❌ Certificate expired');
                return false;
            }

            console.log(`✅ Certificate verified: Serial ${certificate.serial_number}`);
            return true;
        } catch (error) {
            console.error('Certificate verification error:', error);
            return false;
        }
    }

    /**
     * Fetch and verify user certificate from server
     */
    async fetchAndVerifyUserCertificate(userId) {
        // Check cache first
        if (this.certificateCache.has(userId)) {
            const cached = this.certificateCache.get(userId);
            // Verify cache is still valid (< 1 hour old)
            if (Date.now() - cached.cachedAt < 60 * 60 * 1000) {
                return cached.certificate;
            }
        }

        try {
            const response = await axios.get(`http://localhost:5000/api/ca/user/${userId}`);
            const { certificate } = response.data;

            // Verify certificate signature
            const isValid = await this.verifyCertificate(
                certificate,
                certificate.signature
            );

            if (!isValid) {
                throw new Error('Certificate verification failed');
            }

            // Cache valid certificate
            this.certificateCache.set(userId, {
                certificate,
                cachedAt: Date.now()
            });

            return certificate;
        } catch (error) {
            console.error('Failed to fetch user certificate:', error);
            throw error;
        }
    }

    /**
     * Request certificate issuance for current user
     */
    async requestCertificate(userId, publicKeyJWK) {
        try {
            const response = await axios.post('http://localhost:5000/api/ca/issue-certificate', {
                user_id: userId,
                public_key: publicKeyJWK
            });

            const { certificate, signature } = response.data;

            // Verify our own certificate
            const isValid = await this.verifyCertificate(certificate, signature);

            if (!isValid) {
                throw new Error('Issued certificate is invalid');
            }

            console.log('✅ Certificate issued and verified');
            return { certificate, signature };
        } catch (error) {
            console.error('Certificate issuance failed:', error);
            throw error;
        }
    }

    /**
     * Clear certificate cache
     */
    clearCache() {
        this.certificateCache.clear();
        console.log('🧹 Certificate cache cleared');
    }
}

// Singleton instance
const certificateVerifier = new CertificateVerifier();

export default certificateVerifier;
