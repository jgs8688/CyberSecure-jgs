import nodemailer from "nodemailer";
import generateOTP from "../utility/utility.crypto.otp.js";
import express from "express";
import { fileURLToPath } from "url";
import ejs from "ejs";
import path from "path";
import { log } from "console";
import dotenv from "dotenv";
dotenv.config();

const mailRouter = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let storedOTP = null;
let otpExpiresAt = null;

// Setup Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Function to send OTP email with HTML template
async function sendOTPEmail(toEmail, otp) {
  const templatePath = path.join(__dirname, "../utility/mail.ejs");

  const html = await ejs.renderFile(templatePath, { otp });
  
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: toEmail,
    subject: "Verify Your Email - CyberSecure-web",
    html,
  };

  return transporter.sendMail(mailOptions);
}

// Route to send OTP
mailRouter.post("/otp-send", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const otp = generateOTP();
    log("Generated OTP:", otp);
    if (!otp) {
      return res.status(500).json({ message: "Failed to generate OTP" });
    }

    storedOTP = otp;
    otpExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    await sendOTPEmail(email, otp);
    res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error("Error sending OTP email:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Route to verify OTP
mailRouter.post("/verify-otp", (req, res) => {
  const { otp } = req.body;

  if (!otp) {
    return res.status(400).json({ message: "OTP is required" });
  }

  if (!storedOTP || !otpExpiresAt) {
    return res.status(400).json({ message: "No OTP was sent" });
  }

  if (Date.now() > otpExpiresAt) {
    storedOTP = null;
    otpExpiresAt = null;
    return res.status(400).json({ message: "OTP expired" });
  }

  if (otp === storedOTP) {
    storedOTP = null;
    otpExpiresAt = null;
    return res.status(200).json({ message: "Email verified successfully" });
  }

  return res.status(400).json({ message: "Invalid OTP" });
});

export default mailRouter;
