import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routers/authRouter.js";

const app = express();
const PORT=process.env.PORT || 4000;
connectDB();

app.use(express.json())
app.use(cookieParser())
app.use(cors({credentials:true}))

// API endpoints
app.get("/",(req,res)=>{
    res.send("API is working fine")
})
app.use("/api/auth",authRouter)

app.listen(PORT,()=> console.log(`server running on port${PORT}`))