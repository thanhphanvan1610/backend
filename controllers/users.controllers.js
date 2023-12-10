import User from '../models/users.models.js';
import bcrypt from 'bcrypt'
import {HTTP_STATUS} from '../helpers/http_status.js'


const getUsers = async(req, res, next) => {
    try {
        const users = await User.find({});
        if(users.length === 0){
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'List user empty',
                code: HTTP_STATUS.NOT_FOUND
            });
        }
        
        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: users,
            code: HTTP_STATUS.OK
        });
    } catch (error) {
        next(error)
    }
}

const deleteAllUser = async(req, res, next) => {
    try {
        const users = await User.deleteMany({})
        return res.status(HTTP_STATUS.OK).json({
            status: 'deleted all user success!',
            message: users,
            code: HTTP_STATUS.OK
        });
        
    } catch (error) {
        next(error)
    }
}

const updateUser = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { username, password, email, role, avatar, isban, verify } = req.body;
    
        if (!username || !password) {
            return res.status(HTTP_STATUS.BAD_REQUEST).json({
                status: 'failed',
                message: 'Username and password are required',
                code: HTTP_STATUS.BAD_REQUEST
            });
        }

        // Get the current user
        const currentUser = await User.findById(id);

       
        if (username !== currentUser.username) {
            const existingUser = await User.findOne({ username });
            if (existingUser) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Username already taken',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }
        }

        // Check if a user with the new email already exists
        if (email && email !== currentUser.email) {
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                return res.status(HTTP_STATUS.BAD_REQUEST).json({
                    status: 'failed',
                    message: 'Email already taken',
                    code: HTTP_STATUS.BAD_REQUEST
                });
            }
        }

        const salt = await bcrypt.genSalt(10);
        const passwordhashed = await bcrypt.hash(password, salt);
        const updatedUser = await User.findByIdAndUpdate(
            id,
            { username, password: passwordhashed, email, role, avatar, isban, verify },
            { new: true } 
        );

        if (!updatedUser) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'Not Found User',
                code: HTTP_STATUS.NOT_FOUND
            });
        }

        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: 'User updated successful!',
            code: HTTP_STATUS.OK
        });
    } catch (error) {
        
        next(error);
    }
};

const getUserById = async(req, res, next) => {
    const {id} = req.params;
    if (!id) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
            status: 'failed',
            message: 'User ID is required',
            code: HTTP_STATUS.BAD_REQUEST
        });
    }

    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'User not found',
                code: HTTP_STATUS.NOT_FOUND
            });
        }

        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: user,
            code: HTTP_STATUS.OK
        });
        
    } catch (error) {
        next(error);
    }
}

const deleteUser = async(req, res, next) => {
    const {id} = req.params;
    if (!id) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
            status: 'failed',
            message: 'User ID is required',
            code: HTTP_STATUS.BAD_REQUEST
        });
    }

    try {
        const user = await User.findByIdAndDelete(id);
        if (!user) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'User not found',
                code: HTTP_STATUS.NOT_FOUND
            });
        }

        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: 'Successfully deleted the user',
            code: HTTP_STATUS.OK
        });
        
    } catch (error) {
        next(error);
    }
}

const banUser = async(req, res, next) => {
    try {
        const id = req.query.user
        if(!id){
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'required id user',
                code: HTTP_STATUS.BAD_REQUEST
            });
        }
        const banUser = await User.findByIdAndUpdate(id, {isban: true}, {new: true});
        if(!banUser){
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'User not found',
                code: HTTP_STATUS.NOT_FOUND
            });
        }
        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: 'Successfully banned the user',
            code: HTTP_STATUS.OK
        });
    } catch (error) {
        console.log(error.message);
        next(error)
    }
}


const unBanUser = async(req, res, next) => {
    try {
        const id = req.query.user
        if(!id){
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'required id user',
                code: HTTP_STATUS.BAD_REQUEST
            });
        }
        const banUser = await User.findByIdAndUpdate(id, {isban: false}, {new: true});
        if(!banUser){
            return res.status(HTTP_STATUS.NOT_FOUND).json({
                status: 'failed',
                message: 'User not found',
                code: HTTP_STATUS.NOT_FOUND
            });
        }
        return res.status(HTTP_STATUS.OK).json({
            status: 'success',
            message: 'Successfully unbanned the user',
            code: HTTP_STATUS.OK
        });
    } catch (error) {
        console.log(error.message);
        next(error)
    }
}



export {
    getUsers,
    updateUser,
    getUserById,
    deleteUser,
    banUser,
    unBanUser,
    deleteAllUser
}