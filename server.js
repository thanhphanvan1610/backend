import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import bodyParser from 'body-parser';
import {isHttpError} from 'http-errors'
import cookieParser from 'cookie-parser';
import swaggerJsDoc from 'swagger-jsdoc';
import swaggerUI from 'swagger-ui-express';
import connect from './database/connect.js';
import authRoutes from './routes/auth.routes.js';
import userRoutes from './routes/users.routes.js';
import { checkAdmin } from './middlewares/verify_token.js';
import errorRoutes from './routes/error.routes.js';
import './database/redis.js'


const app = express();
const PORT = process.env.PORT;

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({extended: true}));
app.use(bodyParser.json({limit: '1mb'}));


const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: 'AnoTS API',
      version: '1.0.0',
      description: 'AnoTS API Server'
    },
    servers: [
      {
        url: 'http://localhost:3000'
      }
    ]
  },
  apis: ['./routes/*.js']
}

const specs = swaggerJsDoc(options);
app.use('/docs', swaggerUI.serve, swaggerUI.setup(specs))

//middlewares Authentication
app.use('/v1/auth',authRoutes);

app.use('/v1/users', userRoutes)
// app.use('/v1/users', checkAdmin, userRoutes)

// middlewares catch error
app.use(function(req, res, next) {
  res.status(403).end();
});


app.use(errorRoutes);



app.listen(PORT, async() => {
  
    await connect();
    console.log(`Server running on port ${PORT}`);
})