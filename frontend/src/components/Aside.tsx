import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../index.css";
import { axiosInstance } from "../utility/baseUrl";
import { useAuth } from "../context/Authcontext";
import { LoaderCircle, ExternalLink, FileText } from "lucide-react";
import { toast } from "react-toastify";

interface ScanReport {
  _id: string;
  userId: string;
  name: string;
  domain: string;
  pdf: string;
  createdAt: string;
  updatedAt: string;
}

export default function Aside() {
  const { user: userId, setTotalSans } = useAuth();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (!userId) {
      setLoading(false);
      return;
    }

    const fetchData = async () => {
      try {
        setLoading(true);
        const res = await axiosInstance.get(`/url/report/${userId}`, {
          withCredentials: true,
        });

        if (res.status === 200) {
          const userReports = res.data.userReports || [];
          setReports(userReports);
          setTotalSans(userReports.length);
        } else {
          console.error("Error fetching data:", res.statusText);
          toast.error("Failed to fetch reports");
        }
      } catch (err: any) {
        console.error("Fetch error:", err);
        if (err.response?.status === 401) {
          toast.error("Session expired. Please login again.");
          navigate("/signin");
        } else {
          toast.error("Error loading reports");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [userId, setTotalSans, navigate]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleViewAllReports = () => {
    navigate("/reports");
  };

  // Loading UI
  if (loading) {
    return (
      <div className="h-full flex flex-col">
        <div className="bg-white/5 rounded-lg shadow-md p-4 mb-4">
          <h1 className="text-2xl font-bold text-center text-white">User Reports</h1>
          <p className="text-center text-gray-300">Here are your recent scans and reports.</p>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <LoaderCircle className="animate-spin w-8 h-8 text-blue-500" />
        </div>
      </div>
    );
  }

  // No user state
  if (!userId) {
    return (
      <div className="h-full flex flex-col">
        <div className="bg-white/5 rounded-lg shadow-md p-4 mb-4">
          <h1 className="text-2xl font-bold text-center text-white">User Reports</h1>
          <p className="text-center text-gray-300">Please sign in to view your reports.</p>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <button
            onClick={() => navigate("/signin")}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            Sign In
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="bg-white/5 rounded-lg shadow-md p-4 mb-4">
        <h1 className="text-2xl font-bold text-center text-white">User Reports</h1>
        <p className="text-center text-gray-300">
          {reports.length > 0 
            ? `${reports.length} scan${reports.length !== 1 ? 's' : ''} completed`
            : "No scans yet"}
        </p>
      </div>

      {/* Reports List */}
      <div className="flex-1 overflow-y-auto custom-scroll">
        {reports.length === 0 ? (
          <div className="text-center text-gray-400 py-8">
            <FileText className="w-16 h-16 mx-auto mb-4 text-gray-600" />
            <p className="text-lg font-medium mb-2">No reports available</p>
            <p className="text-sm mb-4">Start scanning websites to see reports here</p>
            <button
              onClick={() => navigate("/dashboard")}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm"
            >
              Start Scanning
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {reports.map((item) => (
              <div
                key={item._id}
                className="bg-white/5 rounded-lg shadow-md p-4 hover:bg-white/10 transition-colors border border-gray-700"
              >
                {/* Domain/Title */}
                <div className="flex items-start justify-between mb-2">
                  <h2 className="text-lg font-bold text-white truncate flex-1 mr-2">
                    {item.domain || "Unknown Domain"}
                  </h2>
                  <FileText className="w-5 h-5 text-blue-400 flex-shrink-0" />
                </div>

                {/* URL */}
                <div className="mb-3">
                  <p className="text-sm text-gray-300 mb-1">URL:</p>
                  <a
                    href={item.name}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 text-sm break-all flex items-center gap-1 hover:underline transition-colors"
                  >
                    <span className="truncate">{item.name}</span>
                    <ExternalLink className="w-3 h-3 flex-shrink-0" />
                  </a>
                </div>

                {/* PDF Link and Date */}
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-400">
                      Scanned: {formatDate(item.createdAt)}
                    </p>
                  </div>
                  <a
                    href={item.pdf}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-red-400 hover:text-red-300 text-sm font-medium hover:underline transition-colors flex-shrink-0 ml-2"
                  >
                    📄 Report
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}

            {/* View All Button */}
            {reports.length > 0 && (
              <div className="pt-4 border-t border-gray-700">
                <button
                  onClick={handleViewAllReports}
                  className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm font-medium"
                >
                  View All Reports ({reports.length})
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}