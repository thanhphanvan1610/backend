import mongoose, { Schema } from 'mongoose';

const OTPSchema = new Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users'
    },
    otp: {
        type: String
    },
    create_at:{
        type: Date,
        default: Date.now
    },
    expire_in:{
        type: Date
    }
});



const OTP = mongoose.model('OTP_Verifycation', OTPSchema);
export default OTP;
