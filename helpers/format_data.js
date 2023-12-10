
// function sendErrorResponse(res, message, code = HTTP_STATUS.BAD_REQUEST) {
//     return res.status(code).json({
//         status: 'failed',
//         message,
//         code
//     });
// }

const retrieveData = (user) => {
    
    return {
        username: user.username,
        email: user.email,
        role: user.role,
        verify: user.verify,
        isban: user.isban,
        avatar: user.avatar
    }
}

export default retrieveData;