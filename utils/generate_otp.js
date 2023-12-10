import otpGenerator from 'otp-generator'
import OTP from '../models/otp.models.js';
import EmailModule from '../mails/transporter.js';
import 'dotenv/config'

const generateOTP = () => {
    const randomNumber = otpGenerator.generate(4, {
        upperCase: false,
        specialChars: false,
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false
    });

    return randomNumber;
}
const sendOTP = async(user) => {
    try {
        const emailConfigs = {
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASS
            }
        };

        const userExistOTP = await OTP.findOne({ user_id: user.id });

        if (userExistOTP) {
            await OTP.deleteOne({ user_id: user.id });
        }

        const otp = generateOTP();
        const expire_time = new Date(Date.now() + 20 * 60 * 1000);
        const newOTP = new OTP({ user_id: user, otp, expire_in: expire_time });
        await newOTP.save();

        const emailModule = new EmailModule(emailConfigs);
        const sendOTPTemplate = 'send_otp';
        const sendOTPOptions = {
            from: 'AnoTS Developer',
            to: user.email,
            subject: `AnoTS OTP ${user.username}`,
        };
        const returnMailer = {
            username: user.username,
            email: user.email,
            OTP: otp
        };

        await emailModule.sendEmail(sendOTPTemplate, returnMailer, sendOTPOptions);
        console.log(`Email sent!`);
    } catch (error) {
        console.error(error.message);
        throw new Error('Server Internal Error');
    }
}

export default sendOTP

