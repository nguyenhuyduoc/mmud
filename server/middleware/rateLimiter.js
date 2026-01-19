/**
 * Rate Limiting & Brute-Force Protection Middleware
 * Implements exponential backoff and IP-based tracking
 */

const rateLimit = require('express-rate-limit');

// In-memory store (for production, use Redis)
class MemoryStore {
    constructor() {
        this.hits = new Map();
        this.resetTime = new Map();
    }

    incr(key, cb) {
        const now = Date.now();
        const resetTime = this.resetTime.get(key) || now;

        if (now > resetTime) {
            this.hits.set(key, 1);
            this.resetTime.set(key, now + 60 * 1000); // 15 min window
            return cb(null, 1, new Date(now + 60 * 1000)); // Return Date object
        }

        const hits = (this.hits.get(key) || 0) + 1;
        this.hits.set(key, hits);
        cb(null, hits, new Date(resetTime)); // Return Date object
    }

    decrement(key) {
        const hits = this.hits.get(key) || 0;
        if (hits > 0) {
            this.hits.set(key, hits - 1);
        }
    }

    resetKey(key) {
        this.hits.delete(key);
        this.resetTime.delete(key);
    }
}

const store = new MemoryStore();

// General API rate limiter - 200 requests per 5 minutes (more lenient)
const apiLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 200,
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    store: store
});

// Login rate limiter - 20 failed attempts per 5 minutes PER EMAIL (not per IP)
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes (shorter window)
    max: 20, // More lenient, rely on exponential backoff for security
    skipSuccessfulRequests: true, // Only count failed logins
    //  Track by email instead of IP to allow multiple accounts from same IP
    keyGenerator: (req) => {
        const email = req.body?.email || 'unknown';
        return `login:${email}`;
    },
    message: {
        success: false,
        message: 'Too many failed login attempts. Please try again in a few minutes.'
    },
    handler: (req, res) => {
        const retryAfter = Math.ceil(5 * 60); // 5 minutes
        res.status(429).json({
            success: false,
            message: 'Too many failed login attempts for this email',
            retryAfter: retryAfter,
            lockedUntil: new Date(Date.now() + retryAfter * 1000)
        });
    },
    store: store
});

// Exponential backoff for repeated failures
class ExponentialBackoff {
    constructor() {
        this.attempts = new Map();
        // Clean up old entries every hour
        setInterval(() => this.cleanup(), 60 * 60 * 1000);
    }

    getKey(email, ip) {
        return `${email}:${ip}`;
    }

    async checkAttempt(email, ip) {
        const key = this.getKey(email, ip);
        const data = this.attempts.get(key) || {
            count: 0,
            lockedUntil: null,
            lastAttempt: Date.now()
        };

        // Check if locked
        if (data.lockedUntil && data.lockedUntil > Date.now()) {
            const remainingSeconds = Math.ceil((data.lockedUntil - Date.now()) / 1000);
            throw new Error(
                `Account temporarily locked due to multiple failed attempts. ` +
                `Please try again in ${remainingSeconds} seconds.`
            );
        }

        // Reset if last attempt was > 1 hour ago
        if (Date.now() - data.lastAttempt > 60 * 60 * 1000) {
            data.count = 0;
            data.lockedUntil = null;
        }

        return data;
    }

    recordFailure(email, ip) {
        const key = this.getKey(email, ip);
        const data = this.attempts.get(key) || { count: 0, lockedUntil: null, lastAttempt: Date.now() };

        data.count++;
        data.lastAttempt = Date.now();

        // Exponential backoff: 2^n seconds (max 5 minutes for testing)
        const backoffSeconds = Math.min(Math.pow(2, data.count), 300);
        data.lockedUntil = Date.now() + backoffSeconds * 1000;

        this.attempts.set(key, data);

        return {
            attempts: data.count,
            lockedUntil: data.lockedUntil,
            retryAfter: backoffSeconds
        };
    }

    recordSuccess(email, ip) {
        const key = this.getKey(email, ip);
        this.attempts.delete(key);
    }

    cleanup() {
        const now = Date.now();
        const oneHourAgo = now - 60 * 60 * 1000;

        for (const [key, data] of this.attempts.entries()) {
            if (data.lastAttempt < oneHourAgo) {
                this.attempts.delete(key);
            }
        }
    }

    getAttemptInfo(email, ip) {
        const key = this.getKey(email, ip);
        return this.attempts.get(key);
    }
}

const backoffManager = new ExponentialBackoff();

// IP extraction helper
function getClientIp(req) {
    return req.ip ||
        req.headers['x-forwarded-for']?.split(',')[0] ||
        req.connection.remoteAddress ||
        'unknown';
}

module.exports = {
    apiLimiter,
    loginLimiter,
    backoffManager,
    getClientIp,
    store
};
