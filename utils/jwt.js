import jwt from 'jsonwebtoken';
import 'dotenv/config';
import client from '../database/redis.js';
import util from 'util'

const genAccessToken = (user) => {
    return jwt.sign(
        { id: user.id, username: user.username, role: user.role, isban: user.isban, verify: user.verify },
        process.env.SECRET_ACCESS,
        { expiresIn: '30m' })

}
const genRefreshToken = (user) => {
    const refresh_token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, isban: user.isban, verify: user.verify  },
        process.env.SECRET_REFRESH,
        { expiresIn: '15d' }
    );
    
    client.get(user.username.toString(), (err, data) => {
        if (err) {
            return res.status(500).json({
                status: 'failed',
                message: 'Server Internal Error',
                code: 500
            });
        }
        client.set(user.username.toString(), JSON.stringify({refresh_token: refresh_token}))
    })

    return refresh_token;
}

const getAsync = (key) => {
    return new Promise((resolve, reject) => {
        client.get(key, (err, data) => {
            if (err) {
                reject(err);
            } else if (data === null) {
                reject(new Error(`No value found for key: ${key}`));
            } else {
                resolve(data);
            }
        });
    });
}

const setAsync = util.promisify(client.set).bind(client);
const delAsync = util.promisify(client.del).bind(client);

export {
    genAccessToken,
    genRefreshToken,
    getAsync,
    delAsync,
    setAsync
}