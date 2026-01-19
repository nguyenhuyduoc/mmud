const crypto = require('crypto');

/**
 * Calculate collection-wide checksum for rollback/swap detection
 * @param {string} userId - User's MongoDB ObjectId
 * @returns {Promise<string>} SHA-256 checksum of user's secret collection
 */
async function calculateCollectionChecksum(userId) {
    const Secret = require('../models/Secret');

    try {
        const secrets = await Secret.find({ 'access_list.user_id': userId })
            .select('_id version checksum')
            .sort({ _id: 1 }); // Consistent ordering

        //  Filter out secrets without checksum (legacy data)
        const validSecrets = secrets.filter(s => s.checksum);

        if (validSecrets.length === 0) {
            return crypto.createHash('sha256').update('empty').digest('hex');
        }

        const collectionData = {
            secret_ids: validSecrets.map(s => s._id.toString()),
            versions: validSecrets.map(s => s.version),
            checksums: validSecrets.map(s => s.checksum),
            count: validSecrets.length
        };

        return crypto.createHash('sha256')
            .update(JSON.stringify(collectionData))
            .digest('hex');
    } catch (error) {
        console.error('Error calculating collection checksum:', error);
        throw error;
    }
}

/**
 * Update user's collection checksum and version counter
 * @param {Object} user - User model instance
 */
async function updateUserIntegrity(user) {
    try {
        user.secrets_version += 1;
        user.collection_checksum = await calculateCollectionChecksum(user._id);
        user.last_checksum_update = new Date();
        await user.save();
    } catch (error) {
        console.error('Error updating user integrity:', error);
        throw error;
    }
}

/**
 * Verify user's collection integrity
 * @param {Object} user - User model instance
 * @returns {Promise<{valid: boolean, message: string}>}
 */
async function verifyUserIntegrity(user) {
    try {
        const currentChecksum = await calculateCollectionChecksum(user._id);

        if (!user.collection_checksum) {
            // First time - initialize
            return { valid: true, message: 'First integrity check - initializing' };
        }

        if (currentChecksum !== user.collection_checksum) {
            return {
                valid: false,
                message: 'Collection checksum mismatch - possible rollback or swap attack',
                expected: user.collection_checksum,
                actual: currentChecksum
            };
        }

        return { valid: true, message: 'Collection integrity verified' };
    } catch (error) {
        console.error('Error verifying user integrity:', error);
        return { valid: false, message: `Verification error: ${error.message}` };
    }
}

module.exports = {
    calculateCollectionChecksum,
    updateUserIntegrity,
    verifyUserIntegrity
};
