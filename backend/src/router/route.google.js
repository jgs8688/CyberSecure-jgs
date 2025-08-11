import "../config/googleAuth.js";
import express from "express";
import session from "express-session";
import passport from "passport";
import MongoStore from "connect-mongo";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
const googleRoute = express();
dotenv.config();

googleRoute.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);
googleRoute.use(passport.initialize());
googleRoute.use(passport.session());

// Routes
googleRoute.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"],  prompt: "select_account" })
);

googleRoute.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/", failureMessage: true }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "6h" }
    );
    res.cookie("token", token, {
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production", 
      maxAge: 86400000, 
    });
    console.log(" Google Login Successful:", req.user);
    res.redirect("http://localhost:5173/dashboard");
  }
);


export default googleRoute;
