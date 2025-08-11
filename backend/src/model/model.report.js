import mongoose from "mongoose";

const reportSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    pdf: {
      type: String,
      required: true,
    },
    domain: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Fixed: Removed 'new' keyword - this was the main issue
const ReportData = mongoose.model("ReportData", reportSchema);
export default ReportData;