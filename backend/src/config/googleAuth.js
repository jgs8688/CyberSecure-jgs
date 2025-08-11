import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";
import User from "../model/model.user.js";
import bcrypt from "bcrypt";

dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5000/auth/google/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        const randomPassword = Math.random().toString(36).slice(-6);
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

        const userExists = await User.findOne({
          email: profile.emails[0].value,
        });
        if (userExists) {
          return done(null, userExists);
        }

        const user = await User.create({
          username: profile.displayName,
          email: profile.emails[0].value,
          password: hashedPassword,
        });

        return done(null, user);
      } catch (error) {
        console.error("Error during Google authentication:", error);
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});
