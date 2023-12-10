import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/users.models.js';
import retrieveData from '../helpers/format_data.js';
import { genAccessToken, genRefreshToken } from '../utils/jwt.js';
import { getAsync, delAsync } from '../utils/jwt.js';
import { HTTP_STATUS } from '../helpers/http_status.js'
import mongoose from 'mongoose';
import sendOTP from '../utils/generate_otp.js';
import OTP from '../models/otp.models.js';



class UserAuthService {

    async signUp(req, res, next) {
        try {
            const { username, password, email } = req.body;

            if (!username || !email || !password) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Username, Email and password are required',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }

            if (username.length < 5) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Username must be 5 character!',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }

            // Validate email
            const emailRegex = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;
            if (!emailRegex.test(email)) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Invalid email format',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }

            const existingUser = await User.findOne({ username });  //check exist username
            const existingEmail = await User.findOne({ email });  //check exist email


            if (existingUser || existingEmail) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Username or email already exists',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }

            const salt = await bcrypt.genSalt(10);
            const passwordhashed = await bcrypt.hash(password, salt);

            const user = new User({ username, password: passwordhashed, email });

            await user.save();

            // set refresh Token
            const access_token = genAccessToken(user);
            const refresh_token = genRefreshToken(user)
            res.setHeader('Authorization', 'Bearer ' + access_token)
            res.cookie('refresh_token', refresh_token, {
                httpOnly: true,
                secure: false,
                sameSite: "strict"
            })

            // send Email wellcome!
            await sendOTP(user)
                .catch((err) => {
                    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
                        status: 'failed',
                        message: 'Have an error when send OTP to you',
                        code: HTTP_STATUS.INTERNAL_SERVER_ERROR
                    });
                })

            return res.status(HTTP_STATUS.OK).json({
                status: 'success',
                message: 'Register successful! We sent email to you.',
                verify: user.verify,
                code: HTTP_STATUS.OK
            });


        } catch (error) {
            console.log(error.message)
            next(error);
        }
    }



    async signIn(req, res, next) {
        try {
            const { username, password } = req.body;

            if (!username || !password) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Username or email and password are required',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }

            const user = await User.findOne({ username });

            if (user?.isban === true) {
                return res.status(HTTP_STATUS.FORBIDDEN).json({
                    status: 'failed',
                    message: 'You have been banned',
                    code: HTTP_STATUS.FORBIDDEN
                });
            }

            if (!user) {
                return res.status(HTTP_STATUS.NOT_FOUND).json({
                    status: 'failed',
                    message: 'No user found with the provided username',
                    code: HTTP_STATUS.NOT_FOUND
                });
            }

            const validPassword = await bcrypt.compare(password, user.password);

            if (!validPassword) {
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                    status: 'failed',
                    message: 'Invalid password provided for the given username or email',
                    code: HTTP_STATUS.UNAUTHORIZED
                });
            }

            if (!user.verify) {
                
                    await sendOTP(user);
                    return res.status(HTTP_STATUS.OK).json({
                        status: 'success',
                        message: 'You are not verified! OTP sent to your Email. Please check it.',
                        verify: user.verify,
                        code: HTTP_STATUS.OK
                    });

                

            } else {
                const access_token = genAccessToken(user);
                const refresh_token = genRefreshToken(user);

                res.setHeader('Authorization', 'Bearer ' + access_token);
                res.cookie('refresh_token', refresh_token, {
                    httpOnly: true,
                    secure: false,
                    sameSite: "strict"
                });

                return res.status(HTTP_STATUS.OK).json({
                    status: 'success',
                    message: 'Sign in successful',
                    data: retrieveData(user),
                    code: HTTP_STATUS.OK
                });
            }
        } catch (error) {
            console.error(error.message);
            next(error.message);
        }
    }


    async refreshToken(req, res, next) {
        const refresh_token = req.cookies.refresh_token;
        if (!refresh_token) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                status: 'failed',
                message: 'Unauthenticated',
                code: HTTP_STATUS.UNAUTHORIZED
            });
        }
        try {
            const decode = jwt.verify(refresh_token, process.env.SECRET_REFRESH);

            if (decode && decode.username) {
                const key = decode.username.toString();
                try {
                    const data = await getAsync(key);
                    if (JSON.parse(data)?.refresh_token !== refresh_token) {
                        return res.status(HTTP_STATUS.FORBIDDEN).json({
                            status: 'failed',
                            message: 'Invalid request! refresh token not match',
                            code: HTTP_STATUS.FORBIDDEN
                        });
                    }
                }
                catch (error) {
                    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
                        status: 'failed',
                        message: error.message,
                        code: HTTP_STATUS.INTERNAL_SERVER_ERROR
                    });
                }


            }

            const newAccessToken = genAccessToken(decode);
            const newRefreshToken = genRefreshToken(decode);
            res.cookie('refresh_token', newRefreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: "strict"
            });

            return res.status(HTTP_STATUS.OK).json({
                status: 'success',
                message: 'refresh token successful',
                data: {
                    access_token: newAccessToken
                },
                code: HTTP_STATUS.OK
            });
        } catch (error) {
            console.log(error.message)
            next(error.message)
        }
    }

    async signOut(req, res, next) {
        try {
            const refresh_token = req.cookies.refresh_token;
            if (!refresh_token) {
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                    status: 'failed',
                    message: 'No token provided',
                    code: HTTP_STATUS.UNAUTHORIZED
                });
            }

            const decode = jwt.verify(refresh_token, process.env.SECRET_REFRESH);

            if (decode && decode.username) {
                const key = decode.username.toString();
                const data = await getAsync(key);
                if (JSON.parse(data)?.refresh_token !== refresh_token) {
                    return res.status(HTTP_STATUS.FORBIDDEN).json({
                        status: 'failed',
                        message: 'Invalid request! refresh token not match',
                        code: HTTP_STATUS.FORBIDDEN
                    });
                }

                res.clearCookie('refresh_token');
                await delAsync(key);
                return res.status(HTTP_STATUS.OK).json({
                    status: 'success',
                    message: 'Sign Out successful!',
                    code: HTTP_STATUS.OK
                });
            }
        } catch (error) {
            console.log(error.message)
            next(error)
        }
    }

    async verifyOTP(req, res, next) {
        try {
            const id = req.query.user;
            const otp = req.body.otp;
            if (!id || !otp) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Required OTP',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }
            if (!mongoose.Types.ObjectId.isValid(id)) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Invalid user id',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }
            const user = await User.findById(id)
            if (!user) {
                return res.status(HTTP_STATUS.NOT_FOUND).json({
                    status: 'failed',
                    message: 'Not Found User',
                    code: HTTP_STATUS.NOT_FOUND
                });
            }
            const verifyOTP = await OTP.findOne({ user_id: id })
            if (user.verify === true) {
                return res.status(HTTP_STATUS.OK).json({
                    status: 'success',
                    message: 'User Has Been Confirmed!',
                    code: 250
                });
            }

            if (!verifyOTP) {
                return res.status(HTTP_STATUS.NOT_FOUND).json({
                    status: 'failed',
                    message: 'Not Found your OTP',
                    code: HTTP_STATUS.NOT_FOUND
                });
            }


            if (verifyOTP.expire_in < Date.now()) {
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                    status: 'failed',
                    message: 'OTP expired',
                    code: HTTP_STATUS.UNAUTHORIZED
                });
            }
            if (verifyOTP.otp !== otp) {
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                    status: 'failed',
                    message: 'Incorrect OTP',
                    code: HTTP_STATUS.UNAUTHORIZED
                });
            }
            
            user.verify = true;
            await user.save()
                .then(() => {
                    return res.status(HTTP_STATUS.OK).json({
                        status: 'success',
                        message: 'verify successful!',
                        code: 250
                    });
                })
                .catch((err) => {
                    console.log(err.message)
                    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
                        status: 'failed',
                        message: 'Verify User Failed',
                        code: HTTP_STATUS.UNAUTHORIZED
                    });
                })
        } catch (error) {
            console.log(error.message);
            next(error);
        }
    }

    async sendOTP(req, res, next) {
        try {
            const { email } = req.body;

            // Retrieve the user
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(HTTP_STATUS.NOT_FOUND).json({
                    status: 'failed',
                    message: 'No user found with the provided username',
                    code: HTTP_STATUS.NOT_FOUND
                });
            }

            // Check if the user is banned
            if (user.isban === true) {
                return res.status(HTTP_STATUS.FORBIDDEN).json({
                    status: 'failed',
                    message: 'You have been banned',
                    code: HTTP_STATUS.FORBIDDEN
                });
            }

            // Check if the user is already verified
            if (user.verify === true) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'User is already verified',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }
            await sendOTP(user)
                .then(() => {
                    return res.status(HTTP_STATUS.OK).json({
                        status: 'failed',
                        message: 'We resent OTP to your email!',
                        code: HTTP_STATUS.OK
                    });
                })
                .catch((err) => {
                    console.log(err.message)
                    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
                        status: 'failed',
                        message: 'An error has occurred! try later',
                        code: HTTP_STATUS.INTERNAL_SERVER_ERROR
                    });
                })

        } catch (error) {
            console.log(error.message);
            next(error)
        }
    }



}

export default UserAuthService;
