import mongoose from 'mongoose';

const URI = process.env.URI_DATABASE
const connect = async() => {
    try {
        let connection = await mongoose.connect(URI);
        console.log(`Connected to database!`);
        return connection;
    } catch (error) {
        console.log(`Failed when connect to database with error: ${error.message}`)
    }
}

export default connect