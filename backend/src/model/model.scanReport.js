// src/model/model.scanReport.js
import mongoose from "mongoose";

const scanReportSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  url: { type: String, required: true },
  domain: { type: String },
  phishingDetected: { type: Boolean, default: false },
  malwareDetected: { type: Boolean, default: false },
  reportData: { type: mongoose.Schema.Types.Mixed },  // Store full scan report JSON
  pdfLink: { type: String },
}, { timestamps: true });

const ScanReport = mongoose.model("ScanReport", scanReportSchema);
export default ScanReport;
