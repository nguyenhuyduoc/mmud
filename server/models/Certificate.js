const mongoose = require('mongoose');

const CertificateSchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true  // One active certificate per user
    },
    public_key: {
        type: Object,
        required: true  // JWK format
    },
    issued_at: {
        type: Date,
        default: Date.now
    },
    expires_at: {
        type: Date,
        required: true
    },
    serial_number: {
        type: String,
        unique: true,
        required: true
    },
    signature: {
        type: String,
        required: true  // Hex-encoded ECDSA signature from CA
    },
    status: {
        type: String,
        enum: ['valid', 'revoked', 'expired'],
        default: 'valid'
    },
    revocation_reason: {
        type: String
    },
    revoked_at: {
        type: Date
    }
});

// Index for faster queries
CertificateSchema.index({ user_id: 1, status: 1 });
CertificateSchema.index({ expires_at: 1 });

// Method to check if certificate is currently valid
CertificateSchema.methods.isValid = function () {
    if (this.status !== 'valid') {
        return false;
    }

    if (this.expires_at < new Date()) {
        this.status = 'expired';
        this.save();
        return false;
    }

    return true;
};

// Method to revoke certificate
CertificateSchema.methods.revoke = function (reason) {
    this.status = 'revoked';
    this.revocation_reason = reason;
    this.revoked_at = new Date();
    return this.save();
};

module.exports = mongoose.model('Certificate', CertificateSchema);
