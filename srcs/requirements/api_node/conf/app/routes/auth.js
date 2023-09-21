const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const logInLimiter = rateLimit({
    windowMs : 3 * 60 * 1000, 
    max : 3,
    message : "Nombre de tentative a la suite depasser, veuillez patienter."
})

const checkPassword = require('../middleware/checkPassword');
const isConfirmed = require('../middleware/isConfirmed');
const checkCaptcha = require('../middleware/checkCaptcha');
const auth =  require('../middleware/auth');

const authCtrl = require('../controllers/auth');

router.post('/signup', checkPassword, authCtrl.signUp, authCtrl.logIn);
router.post('/login', logInLimiter, authCtrl.logIn);
router.post('/resend_confirm_mail', auth, authCtrl.resendConfirmationMail);
router.post('/password_reset/:token', checkPassword, authCtrl.passwordReset);
router.post('/password_reset_mail', authCtrl.passwordResetMail);
router.get('/token', authCtrl.refreshToken);
router.get('/me', auth, isConfirmed, authCtrl.getUser);
router.put('/update', auth, isConfirmed, authCtrl.modifyUser);
router.put('/confirm/:token', authCtrl.confirm);
router.delete('/delete', logInLimiter, auth, isConfirmed, authCtrl.deleteUser);

module.exports = router;
