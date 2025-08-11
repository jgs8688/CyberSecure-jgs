import { Router } from "express";
import User from "../model/model.user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { log } from "console";

const userRouter = Router();

//  Signup
userRouter.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, email, password: hashedPassword });
    const savedUser = await newUser.save();

    return res.status(201).json({
      message: "User Created Successfully",
      data: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
      },
    });
  } catch (error) {
    console.error("Signup Error:", error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

//  Signin
userRouter.post("/signin", async (req, res) => {
  console.log("Signin Request Body:", req.body);
  
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });
    log(user);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "6h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.status(200).json({
      message: "Signin Successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Signin Error:", error.message);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Signout
userRouter.get("/signout", (req, res) => {
  res.clearCookie("token");
  return res.status(200).json({ message: "Logout Successful" });
});


// Get User
userRouter.get("/getUser",async(req,res)=>{
  try {
    const userData = await User.find();
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({
      message: "User fetched successfully",
      data: userData, });
      
    
  } catch (error) {
    console.error("Get User Error:", error.message);
    return res.status(500).json({ message: "Internal Server Error" });
    
  }

})

userRouter.get("/getUser/:id",async(req,res)=>{
  const userId =req.params.id;
  console.log("User ID:",userId);
  
try {
  const userData = await User.findById(userId);
  if (!userData) {
    return res.status(404).json({ message: "User not found" });
  }
  return res.status(200).json({
    message: "User fetched successfully",
    data: userData, }); 

} catch (error) {
  console.error("Get User Error:", error.message);
  return res.status(500).json({ message: "Internal Server Error" });
  
}
});

export default userRouter;
