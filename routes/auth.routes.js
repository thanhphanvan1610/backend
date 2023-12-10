import { Router } from 'express';
import UserAuthService from '../controllers/auth.controllers.js';
import { verifyAccessToken } from '../middlewares/verify_token.js';
import { OTPLimiter, AuthLimiter, OTPAttemptLimiter } from '../utils/limited_request.js';
const auth = new UserAuthService();
const router = Router();

router.post('/signup',auth.signUp.bind(auth));
router.post('/signin',auth.signIn.bind(auth));
router.post('/refresh', auth.refreshToken.bind(auth));
router.delete('/logout', verifyAccessToken,auth.signOut.bind(auth));
router.post('/verify', OTPAttemptLimiter ,auth.verifyOTP.bind(auth));
router.post('/resend', OTPLimiter,auth.sendOTP.bind(auth));


const authRoutes = router;
export default authRoutes;