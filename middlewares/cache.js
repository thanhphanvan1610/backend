import { setAsync, getAsync } from "../helpers/jwt.js"

const cache = async (req, res, next) => {
    const key = req.route.path;
    let data = await getAsync(key);

    if (data) {
        console.log('Fetching data from cache...');
        res.send(JSON.parse(data));
    } else {
        res.locals.data = data;
        next();
    }
};

export default cache;
