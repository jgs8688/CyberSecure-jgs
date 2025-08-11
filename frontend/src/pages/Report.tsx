import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { axiosInstance } from "../utility/baseUrl";
import { toast } from "react-toastify";
import { useAuth } from "../context/Authcontext";
import { FileText, Globe, LoaderCircle, ArrowLeft, ExternalLink } from "lucide-react";

interface ReportItem {
  _id: string;
  userId: string;
  name: string;
  domain: string;
  pdf: string;
  createdAt: string;
  updatedAt: string;
}

const Report: React.FC = () => {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(false);
  const { user, setTotalSans } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate("/signin");
      return;
    }

    const fetchReports = async () => {
      try {
        setLoading(true);
        const response = await axiosInstance.get(`/url/report/${user}`, {
          withCredentials: true,
        });
        
        if (response.status === 200) {
          const userReports = response.data.userReports || [];
          setReports(userReports);
          setTotalSans(userReports.length);
        } else {
          toast.error("Failed to fetch reports.");
        }
      } catch (error: any) {
        console.error("Error fetching reports:", error);
        if (error.response?.status === 401) {
          toast.error("Session expired. Please login again.");
          navigate("/signin");
        } else {
          toast.error("Something went wrong while fetching reports.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, [user, navigate, setTotalSans]);

  const handleBackToDashboard = () => {
    navigate("/dashboard");
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0f1115]">
        <LoaderCircle className="animate-spin w-12 h-12 text-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f1115] text-white">
      {/* Header */}
      <div className="bg-[#1c1f26] border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={handleBackToDashboard}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Dashboard
            </button>
            <h1 className="text-3xl font-bold">Scan Reports</h1>
          </div>
          <span className="text-sm text-gray-400 bg-gray-800 px-3 py-1 rounded-full">
            Total: {reports.length}
          </span>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6">
        {reports.length === 0 ? (
          <div className="text-center py-20">
            <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h2 className="text-2xl font-semibold text-gray-400 mb-2">No Reports Found</h2>
            <p className="text-gray-500 mb-6">
              You haven't performed any scans yet. Start scanning websites to see reports here.
            </p>
            <button
              onClick={handleBackToDashboard}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Start Your First Scan
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {reports.map((report) => (
              <div
                key={report._id}
                className="bg-[#1c1f26] rounded-lg p-6 shadow-lg hover:bg-[#272b32] transition-all duration-300 hover:shadow-xl border border-gray-800"
              >
                {/* Report Header */}
                <div className="flex items-start gap-3 mb-4">
                  <FileText className="text-blue-500 w-6 h-6 flex-shrink-0 mt-1" />
                  <div className="flex-1 min-w-0">
                    <h3 className="text-lg font-semibold text-white truncate mb-1">
                      {report.domain}
                    </h3>
                    <div className="flex items-center gap-2 text-gray-400 text-sm">
                      <Globe className="w-4 h-4 text-green-400 flex-shrink-0" />
                      <span className="truncate">{report.name}</span>
                    </div>
                  </div>
                </div>

                {/* Report Details */}
                <div className="space-y-3">
                  <div className="text-sm text-gray-400">
                    <span className="text-gray-500">Scanned:</span>
                    <br />
                    <span className="text-white">{formatDate(report.createdAt)}</span>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col gap-2 pt-2">
                    <a
                      href={report.pdf}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                      View PDF Report
                    </a>
                    
                    <a
                      href={report.name}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded-lg transition-colors"
                    >
                      <Globe className="w-4 h-4" />
                      Visit Website
                    </a>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Load More Button (if needed) */}
        {reports.length > 0 && (
          <div className="text-center mt-8">
            <p className="text-gray-400 text-sm">
              Showing all {reports.length} report{reports.length !== 1 ? 's' : ''}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Report;