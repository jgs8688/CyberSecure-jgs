import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  UserCircle,
  FileDown,
  ShieldCheck,
  Mail,
  Calendar,
  ArrowLeft,
  LoaderCircle,
} from "lucide-react";
import { useAuth } from "../context/Authcontext";
import { axiosInstance } from "../utility/baseUrl";
import { toast } from "react-toastify";

interface ReportItem {
  _id: string;
  name: string;
  domain: string;
  pdf: string;
  createdAt: string;
}

interface UserData {
  username: string;
  email: string;
  createdAt: string;
}

const UserProfile: React.FC = () => {
  const [userInfo, setUserInfo] = useState<UserData | null>(null);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingReport, setDownloadingReport] = useState(false);

  const { user, setTotalSans } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate("/signin");
      return;
    }

    const fetchUserData = async () => {
      try {
        const res = await axiosInstance.get(`/user/getUser/${user}`, {
          withCredentials: true,
        });

        if (res.status === 200) {
          setUserInfo(res.data.data);
        } else {
          toast.error("Failed to fetch user data");
        }
      } catch (error: any) {
        console.error("Error fetching user data:", error);
        if (error.response?.status === 401) {
          toast.error("Session expired. Please login again.");
          navigate("/signin");
        } else {
          toast.error("Error fetching user data");
        }
      }
    };

    fetchUserData();
  }, [user, navigate]);

  useEffect(() => {
    if (!user) return;

    const fetchReports = async () => {
      try {
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
        if (error.response?.status !== 401) {
          toast.error("Something went wrong while fetching reports.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, [user, setTotalSans]);

  const handleBackToDashboard = () => {
    navigate("/dashboard");
  };

  const handleDownloadSummary = async () => {
    setDownloadingReport(true);
    try {
      // This is a placeholder for the actual download functionality
      // You would implement the actual PDF generation or summary download here
      toast.info("Download summary feature coming soon!");
      
      // Example of how you might implement this:
      /*
      const response = await axiosInstance.get(`/user/download-summary/${user}`, {
        withCredentials: true,
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-summary-${userInfo?.username}.pdf`;
      link.click();
      window.URL.revokeObjectURL(url);
      */
    } catch (error) {
      toast.error("Failed to download summary");
    } finally {
      setDownloadingReport(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
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
    <div className="min-h-screen w-full bg-gradient-to-br from-[#0f1115] via-[#12141b] to-[#1c1f26]">
      {/* Header */}
      <div className="bg-[#1c1f26] border-b border-gray-700 px-6 py-4">
        <div className="flex items-center gap-4">
          <button
            onClick={handleBackToDashboard}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </button>
          <h1 className="text-3xl font-bold text-white">User Profile</h1>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex items-center justify-center px-4 py-10">
        <div className="w-full max-w-4xl bg-[#1c1f26] text-white rounded-2xl shadow-xl p-10 relative overflow-hidden transition-all duration-300 hover:shadow-2xl border border-gray-800">
          
          {/* Profile Header */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-6 mb-8">
            <UserCircle className="w-24 h-24 text-blue-400 drop-shadow-lg" />
            <div className="text-center md:text-left flex-1">
              <h2 className="text-3xl font-extrabold tracking-wide mb-2">
                {userInfo?.username || "Loading..."}
              </h2>
              <div className="flex items-center gap-2 text-gray-400 justify-center md:justify-start">
                <Mail className="w-4 h-4" />
                <span className="break-all">{userInfo?.email || "Loading..."}</span>
              </div>
              {userInfo?.createdAt && (
                <div className="flex items-center gap-2 text-gray-400 mt-2 justify-center md:justify-start">
                  <Calendar className="w-4 h-4" />
                  <span>Joined {formatDate(userInfo.createdAt)}</span>
                </div>
              )}
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-gray-700 my-8"></div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-[#2a2d36] p-6 rounded-lg shadow-inner flex flex-col items-center text-center">
              <ShieldCheck className="text-green-400 w-8 h-8 mb-3" />
              <span className="text-2xl font-bold text-blue-300 mb-1">{reports.length}</span>
              <span className="text-base font-medium text-gray-300">Total Scans</span>
            </div>

            <div className="bg-[#2a2d36] p-6 rounded-lg shadow-inner flex flex-col items-center text-center">
              <FileDown className="text-blue-400 w-8 h-8 mb-3" />
              <span className="text-2xl font-bold text-blue-300 mb-1">{reports.length}</span>
              <span className="text-base font-medium text-gray-300">Reports Generated</span>
            </div>

            <div className="bg-[#2a2d36] p-6 rounded-lg shadow-inner flex flex-col items-center text-center">
              <Calendar className="text-yellow-400 w-8 h-8 mb-3" />
              <span className="text-2xl font-bold text-blue-300 mb-1">
                {userInfo?.createdAt ? 
                  Math.floor((new Date().getTime() - new Date(userInfo.createdAt).getTime()) / (1000 * 60 * 60 * 24)) 
                  : 0}
              </span>
              <span className="text-base font-medium text-gray-300">Days Active</span>
            </div>
          </div>

          {/* Recent Activity */}
          {reports.length > 0 && (
            <div className="mb-8">
              <h3 className="text-xl font-semibold mb-4 text-center">Recent Scans</h3>
              <div className="bg-[#2a2d36] rounded-lg p-4 max-h-60 overflow-y-auto">
                {reports.slice(0, 5).map((report) => (
                  <div key={report._id} className="flex justify-between items-center py-2 border-b border-gray-700 last:border-b-0">
                    <div>
                      <p className="text-white font-medium">{report.domain}</p>
                      <p className="text-gray-400 text-sm">{formatDate(report.createdAt)}</p>
                    </div>
                    <a
                      href={report.pdf}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 text-sm"
                    >
                      View Report
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button
              onClick={handleDownloadSummary}
              disabled={downloadingReport}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-6 py-3 rounded-full text-white flex items-center justify-center gap-3 font-medium transition duration-300 min-w-[200px]"
            >
              {downloadingReport ? (
                <LoaderCircle className="w-5 h-5 animate-spin" />
              ) : (
                <FileDown className="w-5 h-5" />
              )}
              {downloadingReport ? "Generating..." : "Download Summary"}
            </button>

            <button
              onClick={() => navigate("/reports")}
              className="bg-gray-600 hover:bg-gray-700 px-6 py-3 rounded-full text-white flex items-center justify-center gap-3 font-medium transition duration-300 min-w-[200px]"
            >
              <ShieldCheck className="w-5 h-5" />
              View All Reports
            </button>
          </div>

          {/* No Data Message */}
          {reports.length === 0 && (
            <div className="text-center py-8">
              <ShieldCheck className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">No Scans Yet</h3>
              <p className="text-gray-500 mb-4">
                Start scanning websites to see your security reports here.
              </p>
              <button
                onClick={handleBackToDashboard}
                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                Start Your First Scan
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserProfile;