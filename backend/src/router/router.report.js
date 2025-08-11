import express from "express";
import ReportData from "../model/model.report.js";
import authMiddleware from "../middleware/authMiddleware.js"; // Import auth middleware

const reportRouter = express.Router();

// Apply auth middleware to protect report routes
reportRouter.use(authMiddleware);

// to report a url (this might be redundant since scan controller now saves reports)
reportRouter.post("/report", async (req, res) => {
  const { userId, name, domain, pdf } = req.body;
  
  if (!name || !userId || !domain) {
    return res.status(400).json({ message: "name, userId, and domain are required" });
  }
  
  try {
    const reportData = new ReportData({
      userId,
      name,
      domain,
      pdf,
    });
    
    const savedReport = await reportData.save();
    
    if (!savedReport) {
      return res.status(500).json({ message: "Failed to save report" });
    }
    
    console.log("Report saved successfully:", savedReport);
    return res.status(200).json({ 
      message: "Report saved successfully", 
      report: savedReport 
    });
  } catch (error) {
    console.error("Error reporting URL:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});

// to get a report by userId
reportRouter.get("/report/:userId", async (req, res) => {
  const { userId } = req.params;
  
  if (!userId) {
    return res.status(400).json({ message: "userId required" });
  }
  
  try {
    const userReports = await ReportData.find({ userId })
      .sort({ createdAt: -1 })
      .lean(); // Use lean() for better performance
    
    console.log("User report fetched successfully. Count:", userReports.length);
    return res.status(200).json({
      userReports: userReports || []
    });
  } catch (error) {
    console.error("Error fetching report:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});

// Get all reports (admin route - optional)
reportRouter.get("/reports/all", async (req, res) => {
  try {
    const allReports = await ReportData.find()
      .populate('userId', 'username email') // Populate user info
      .sort({ createdAt: -1 })
      .lean();
    
    return res.status(200).json({
      reports: allReports,
      count: allReports.length
    });
  } catch (error) {
    console.error("Error fetching all reports:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});

// Delete a report by ID
reportRouter.delete("/report/:reportId", async (req, res) => {
  const { reportId } = req.params;
  const userId = req.user.id || req.userId;
  
  try {
    const report = await ReportData.findOneAndDelete({ 
      _id: reportId, 
      userId: userId // Ensure user can only delete their own reports
    });
    
    if (!report) {
      return res.status(404).json({ message: "Report not found or unauthorized" });
    }
    
    return res.status(200).json({ message: "Report deleted successfully" });
  } catch (error) {
    console.error("Error deleting report:", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});

export default reportRouter;