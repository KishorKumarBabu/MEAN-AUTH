import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/usermodels.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.json({ success: false, message: "Messing Details..." });
  }

  try {
    const exisingUser = await userModel.findOne({ email });
    if (exisingUser) {
      return res.json({ success: false, message: "user already exising" });
    }
    const hashedpassword = await bcrypt.hash(password, 10);
    const user = new userModel({ name, email, password: hashedpassword });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.Cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      secure: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({
      success: false,
      message: "email and password is required",
    });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "user not found" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "invalid Password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.Cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      secure: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({ success: true });

  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const logout = (req, res)=>{
    try {
      res.clearCookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      secure: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({success:true, message:"logout sucessfully"})
        
    } catch (error) {
        return res.json({success:false, message:error.message})
    }
}
