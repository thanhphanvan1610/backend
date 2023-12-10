import rateLimiter from 'express-rate-limit'

const OTPLimiter = rateLimiter({
    windowMs: 15 * 1000 * 60,
    max: 3,
    handler: function (req, res) {
        res.status(429).json({status: 'failed', message: 'Too many requests, Wait 15 minutes and try again.' });
    }
})
const AuthLimiter = rateLimiter({
    windowMs: 5 * 1000 * 60,
    max: 4,
    handler: function (req, res) {
        res.status(429).json({
            status: 'failed',
            message: 'Too many requests, please try again later after 5 minutes.',
            code: 429
        });
    }
})

const OTPAttemptLimiter = rateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 incorrect attempts per windowMs
    handler: function(req, res /*, next */) {
        const retryAfter = Math.ceil(this.windowMs / 1000 /60);
        res.status(429).json({ 
            message: 'Too many OTP attempts, please try again later.',
            retryAfter: `${retryAfter} minutes`
        });
    }
})

export { OTPLimiter, AuthLimiter, OTPAttemptLimiter }
