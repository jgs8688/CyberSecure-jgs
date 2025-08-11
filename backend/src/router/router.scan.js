import express from "express";
import { scanWebsite } from "../controllers/scanController.js";
import authMiddleware from "../middleware/authMiddleware.js"; // Import auth middleware

const scanRouter = express.Router();

// Apply auth middleware to protect the scan route
scanRouter.post("/scan", authMiddleware, scanWebsite);

export default scanRouter;