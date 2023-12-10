import redis from 'redis';
import 'dotenv/config'

const client = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
   
});

client.on('connect', () => {
    console.log(`Redis client connected`);
});

client.on('error', (err) => {
    console.log(`Redis client could not connect: ${err}`);
});

export default client;
