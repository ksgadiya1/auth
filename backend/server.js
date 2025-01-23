import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import { connectDB } from "./config/mongodb.js";
import authRoutes from './routes/authRoutes.js'


const app = express();  

const port = process.env.PORT ||  4000

app.use(express.json());
app.use(cookieParser());
app.use(cors({Credentials:true}))

connectDB();

// api end points
app.get('/', (req, res) => res.send("API is working fine"))
app.use('/api/auth', authRoutes)

app.listen( port, ()=> console.log(`server started on PORT | ${port}`));
 





