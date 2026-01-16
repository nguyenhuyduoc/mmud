const express = require('express');
const router = express.Router();
const ca = require('../utils/certificateAuthority');
const Certificate = require('../models/Certificate');

// Get CA public key (for client-side verification)
router.get('/public-key', async (req, res) => {
    try {
        const publicKey = await ca.getPublicKey();
        res.json({
            success: true,
            ca_public_key: publicKey
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to get CA public key',
            error: error.message
        });
    }
});

// Issue certificate for a user  
router.post('/issue-certificate', async (req, res) => {
    try {
        const { user_id, public_key } = req.body;

        if (!user_id || !public_key) {
            return res.status(400).json({
                success: false,
                message: 'Missing user_id or public_key'
            });
        }

        // Check if user already has a valid certificate
        const existingCert = await Certificate.findOne({
            user_id,
            status: 'valid'
        });

        if (existingCert && existingCert.isValid()) {
            return res.status(400).json({
                success: false,
                message: 'User already has a valid certificate',
                serial_number: existingCert.serial_number
            });
        }

        const result = await ca.issueCertificate(user_id, public_key);

        res.status(201).json({
            success: true,
            message: 'Certificate issued successfully',
            ...result
        });
    } catch (error) {
        console.error('Certificate issuance error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to issue certificate',
            error: error.message
        });
    }
});

// Verify a certificate
router.post('/verify-certificate', async (req, res) => {
    try {
        const { certificate, signature } = req.body;

        if (!certificate || !signature) {
            return res.status(400).json({
                success: false,
                message: 'Missing certificate or signature'
            });
        }

        const result = await ca.verifyCertificate(certificate, signature);

        res.json({
            success: result.valid,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Verification failed',
            error: error.message
        });
    }
});

// Revoke a certificate
router.post('/revoke-certificate', async (req, res) => {
    try {
        const { serial_number, reason } = req.body;

        if (!serial_number) {
            return res.status(400).json({
                success: false,
                message: 'Missing serial_number'
            });
        }

        const cert = await ca.revokeCertificate(serial_number, reason);

        res.json({
            success: true,
            message: 'Certificate revoked',
            certificate: {
                serial_number: cert.serial_number,
                status: cert.status,
                revoked_at: cert.revoked_at,
                revocation_reason: cert.revocation_reason
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Revocation failed',
            error: error.message
        });
    }
});

// Get certificate by user_id
router.get('/user/:user_id', async (req, res) => {
    try {
        const { user_id } = req.params;

        const cert = await Certificate.findOne({
            user_id,
            status: 'valid'
        });

        if (!cert) {
            return res.status(404).json({
                success: false,
                message: 'No valid certificate found for user'
            });
        }

        res.json({
            success: true,
            certificate: {
                user_id: cert.user_id,
                public_key: cert.public_key,
                issued_at: cert.issued_at,
                expires_at: cert.expires_at,
                serial_number: cert.serial_number,
                signature: cert.signature,
                status: cert.status
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve certificate',
            error: error.message
        });
    }
});

module.exports = router;
