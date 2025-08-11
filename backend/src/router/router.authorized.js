import { log } from "console";
import e, { Router } from "express";
import jwt from "jsonwebtoken";


const authorized = Router();

// userRouter is the route for user authentication

authorized.get("/authorized", (req, res) => {
  const token = req.cookies.token;
  log("Token from cookies:", token);

  try {
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("Token verification error:", err);
        return res.status(401).json({ message: err.message });
      }
      log("Decoded token:", decoded);
      return res.status(200).json({ message: "Authorized", user: decoded });
    });
  } catch (error) {
    console.error("Error in authorized route:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

export default authorized;
