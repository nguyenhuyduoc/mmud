/**
 * Certificate Authority Service
 * Handles certificate issuance, verification, and revocation
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const Certificate = require('../models/Certificate');

class CertificateAuthority {
    constructor() {
        this.caKeyPair = null;
        this.caPublicKeyJWK = null;
        this.initialized = false;
    }

    /**
     * Initialize CA with keypair (load or generate)
     */
    async initialize() {
        if (this.initialized) return;

        const keyPath = path.join(__dirname, '../.ca-keys');
        const privateKeyPath = path.join(keyPath, 'ca-private.json');
        const publicKeyPath = path.join(keyPath, 'ca-public.json');

        try {
            // Try to load existing keys
            const privateKeyData = await fs.readFile(privateKeyPath, 'utf8');
            const publicKeyData = await fs.readFile(publicKeyPath, 'utf8');

            const privateKeyJWK = JSON.parse(privateKeyData);
            const publicKeyJWK = JSON.parse(publicKeyData);

            const { subtle } = require('node:crypto').webcrypto;

            this.caKeyPair = {
                sec: await subtle.importKey('jwk', privateKeyJWK,
                    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']),
                pub: await subtle.importKey('jwk', publicKeyJWK,
                    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['verify'])
            };

            this.caPublicKeyJWK = publicKeyJWK;

            console.log(' CA keys loaded from disk');
        } catch (error) {
            // Generate new CA keypair
            console.log(' Generating new CA keypair...');
            await this.generateCAKeys();

            // Save to disk
            try {
                await fs.mkdir(keyPath, { recursive: true });

                const { subtle } = require('node:crypto').webcrypto;
                const privateKeyJWK = await subtle.exportKey('jwk', this.caKeyPair.sec);
                const publicKeyJWK = await subtle.exportKey('jwk', this.caKeyPair.pub);

                await fs.writeFile(privateKeyPath, JSON.stringify(privateKeyJWK, null, 2));
                await fs.writeFile(publicKeyPath, JSON.stringify(publicKeyJWK, null, 2));

                this.caPublicKeyJWK = publicKeyJWK;

                console.log(' CA keys generated and saved');
            } catch (saveError) {
                console.error('  Failed to save CA keys:', saveError.message);
            }
        }

        this.initialized = true;
    }

    /**
     * Generate CA ECDSA keypair
     */
    async generateCAKeys() {
        const { subtle } = require('node:crypto').webcrypto;

        const keypair = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign', 'verify']
        );

        this.caKeyPair = {
            pub: keypair.publicKey,
            sec: keypair.privateKey
        };
    }

    /**
     * Generate unique serial number for certificate
     */
    generateSerialNumber() {
        return crypto.randomBytes(16).toString('hex');
    }

    /**
     * Issue a new certificate for a user
     */
    async issueCertificate(userId, publicKeyJWK) {
        await this.initialize();

        const serialNumber = this.generateSerialNumber();
        const issuedAt = new Date();
        const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

        // Create certificate data
        const certData = {
            user_id: userId.toString(),
            public_key: publicKeyJWK,
            issued_at: issuedAt.toISOString(),
            expires_at: expiresAt.toISOString(),
            serial_number: serialNumber
        };

        // Sign certificate with CA private key
        const certString = JSON.stringify(certData);
        const { subtle } = require('node:crypto').webcrypto;

        const signatureBuffer = await subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-384' } },
            this.caKeyPair.sec,
            Buffer.from(certString)
        );

        const signature = Buffer.from(signatureBuffer).toString('hex');

        // Save to database
        const certificate = new Certificate({
            user_id: userId,
            public_key: publicKeyJWK,
            issued_at: issuedAt,
            expires_at: expiresAt,
            serial_number: serialNumber,
            signature: signature,
            status: 'valid'
        });

        await certificate.save();

        console.log(` Certificate issued for user ${userId} - Serial: ${serialNumber}`);

        return {
            certificate: certData,
            signature: signature
        };
    }

    /**
     * Verify certificate signature
     */
    async verifyCertificate(certData, signature) {
        await this.initialize();

        try {
            const certString = JSON.stringify(certData);
            const { subtle } = require('node:crypto').webcrypto;

            const signatureBuffer = Buffer.from(signature, 'hex');

            const isValid = await subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-384' } },
                this.caKeyPair.pub,
                signatureBuffer,
                Buffer.from(certString)
            );

            if (!isValid) {
                return { valid: false, reason: 'Invalid signature' };
            }

            // Check expiration
            const expiresAt = new Date(certData.expires_at);
            if (expiresAt < new Date()) {
                return { valid: false, reason: 'Certificate expired' };
            }

            // Check revocation status in database
            const dbCert = await Certificate.findOne({ serial_number: certData.serial_number });
            if (dbCert && !dbCert.isValid()) {
                return { valid: false, reason: `Certificate ${dbCert.status}` };
            }

            return { valid: true };
        } catch (error) {
            console.error('Certificate verification error:', error);
            return { valid: false, reason: error.message };
        }
    }

    /**
     * Revoke a certificate
     */
    async revokeCertificate(serialNumber, reason = 'User requested') {
        const cert = await Certificate.findOne({ serial_number: serialNumber });

        if (!cert) {
            throw new Error('Certificate not found');
        }

        await cert.revoke(reason);
        console.log(` Certificate revoked: ${serialNumber} - Reason: ${reason}`);

        return cert;
    }

    /**
     * Get CA public key (for client verification)
     */
    async getPublicKey() {
        await this.initialize();
        return this.caPublicKeyJWK;
    }

    /**
     * Clean up expired certificates (background job)
     */
    async cleanupExpiredCertificates() {
        const result = await Certificate.updateMany(
            {
                expires_at: { $lt: new Date() },
                status: 'valid'
            },
            {
                $set: { status: 'expired' }
            }
        );

        if (result.modifiedCount > 0) {
            console.log(` Marked ${result.modifiedCount} certificates as expired`);
        }
    }
}

// Singleton instance
const ca = new CertificateAuthority();

// Auto-cleanup expired certificates every 24 hours
setInterval(() => {
    ca.cleanupExpiredCertificates().catch(console.error);
}, 24 * 60 * 60 * 1000);

module.exports = ca;
