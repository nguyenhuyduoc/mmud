/**
 * Key Rotation Service for Forward Secrecy
 * Background job to automatically rotate secret encryption keys
 */

const Secret = require('../models/Secret');
const AuditLog = require('../models/AuditLog');

class KeyRotationService {
    constructor() {
        this.rotationJob = null;
    }

    /**
     * Start automatic key rotation background job
     */
    startRotationScheduler() {
        // Check every 24 hours for secrets that need rotation
        this.rotationJob = setInterval(async () => {
            try {
                await this.checkAndRotateKeys();
            } catch (error) {
                console.error('Key rotation scheduler error:', error);
            }
        }, 24 * 60 * 60 * 1000);

        console.log('🔄 Key rotation scheduler started');
    }

    /**
     * Check all secrets and rotate keys if needed
     */
    async checkAndRotateKeys() {
        const now = new Date();

        // Find secrets with auto_rotate enabled and past due
        const secretsToRotate = await Secret.find({
            'rotation_policy.auto_rotate': true,
            'rotation_policy.next_rotation': { $lt: now }
        });

        console.log(`Found ${secretsToRotate.length} secrets to rotate`);

        for (const secret of secretsToRotate) {
            try {
                await this.rotateSecretKey(secret._id);
            } catch (error) {
                console.error(`Failed to rotate secret ${secret._id}:`, error);
            }
        }
    }

    /**
     * Rotate encryption key for a specific secret
     * This creates a new key version while maintaining access to old versions
     */
    async rotateSecretKey(secretId) {
        const secret = await Secret.findById(secretId);
        if (!secret) {
            throw new Error('Secret not found');
        }

        const newVersion = secret.current_version + 1;
        const now = new Date();

        // Mark current version as expiring soon (but still accessible for 30 days)
        if (secret.key_versions && secret.key_versions.length > 0) {
            const currentVersion = secret.key_versions.find(
                v => v.version === secret.current_version
            );
            if (currentVersion && !currentVersion.expires_at) {
                currentVersion.expires_at = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
            }
        }

        // Add new key version (client will handle re-encryption)
        secret.version = newVersion;
        secret.current_version = newVersion;

        // Update rotation timestamps
        secret.rotation_policy.last_rotation = now;
        secret.rotation_policy.next_rotation = new Date(
            now.getTime() + secret.rotation_policy.rotation_interval_days * 24 * 60 * 60 * 1000
        );

        await secret.save();

        // Log rotation event
        await AuditLog.create({
            action: 'key_rotation',
            user_id: secret.owner,
            secret_id: secretId,
            metadata: {
                old_version: secret.current_version - 1,
                new_version: newVersion,
                rotated_at: now
            },
            ip_address: 'system',
            user_agent: 'key-rotation-service'
        });

        console.log(`🔄 Rotated key for secret ${secretId} to version ${newVersion}`);
        return secret;
    }

    /**
     * Manually trigger key rotation for a secret
     */
    async manualRotation(secretId, userId) {
        const secret = await Secret.findById(secretId);
        if (!secret) {
            throw new Error('Secret not found');
        }

        // Check if user has permission
        const userAccess = secret.access_list.find(
            a => a.user_id.toString() === userId.toString()
        );

        if (!userAccess || !userAccess.permissions.can_edit) {
            throw new Error('Insufficient permissions for key rotation');
        }

        return await this.rotateSecretKey(secretId);
    }

    /**
     * Clean up expired key versions
     * Remove key versions that expired more than 90 days ago
     */
    async cleanupExpiredVersions() {
        const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

        const result = await Secret.updateMany(
            {},
            {
                $pull: {
                    key_versions: {
                        expires_at: { $lt: cutoffDate }
                    }
                }
            }
        );

        console.log(`🧹 Cleaned up expired key versions: ${result.modifiedCount} secrets updated`);
    }

    /**
     * Stop rotation scheduler
     */
    stopRotationScheduler() {
        if (this.rotationJob) {
            clearInterval(this.rotationJob);
            console.log('⏹️  Key rotation scheduler stopped');
        }
    }
}

// Singleton instance
const keyRotationService = new KeyRotationService();

module.exports = keyRotationService;
