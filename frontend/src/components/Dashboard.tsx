import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/Authcontext";
import { axiosInstance } from "../utility/baseUrl";
import ScanForm from "./ScanForm";
import {
  LayoutDashboard,
  Globe,
  Bug,
  ShieldCheck,
  X,
  Menu,
  User,
  LoaderCircle,
  LogOut,
} from "lucide-react";

import logo from "../../public/assets/Logo.svg";
import { toast } from "react-toastify";

interface UserData {
  username: string;
  email: string;
}

interface ReportItem {
  _id: string;
  userId: string;
  name: string;
  domain: string;
  pdf: string;
  createdAt: string;
  updatedAt: string;
}

const Dashboard: React.FC = () => {
  const [userData, setUserData] = useState<UserData>();
  const { user: id, setUser, totalSans, setTotalSans } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [showScanForm, setShowScanForm] = useState(false); // Better state management
  const [reports, setReports] = useState<ReportItem[]>([]);

  const navigate = useNavigate();

  useEffect(() => {
    if (!id) {
      navigate("/signin");
      return;
    }

    const userDatas = async () => {
      try {
        const res = await axiosInstance.get(`/user/getUser/${id}`, {
          withCredentials: true,
        });

        if (res.status === 200) {
          setUserData(res.data.data);
        }
      } catch (error) {
        console.error("Error fetching user data:", error);
        toast.error("Failed to fetch user data");
      }
    };
    userDatas();
  }, [id, navigate]);

  useEffect(() => {
    if (!id) return;

    const fetchReports = async () => {
      try {
        const response = await axiosInstance.get(`/url/report/${id}`, {
          withCredentials: true,
        });

        if (response.status === 200) {
          setReports(response.data.userReports || []);
          setTotalSans(response.data.userReports?.length || 0);
        } else {
          toast.error("Failed to fetch reports.");
        }
      } catch (error) {
        console.error("Error fetching reports:", error);
      }
    };

    fetchReports();
  }, [id, setTotalSans]);

  const handleSignOut = async () => {
    try {
      const res = await axiosInstance.get("/user/signout", {
        withCredentials: true,
      });
      if (res.status === 200) {
        setUser(null);
        navigate("/");
        toast.success("Signed out successfully");
      }
    } catch (error) {
      console.error("Sign out error:", error);
      toast.error("Failed to sign out");
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    
    if (!url.trim()) {
      toast.error("Please enter a URL to scan.");
      setLoading(false);
      return;
    }
    
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      toast.error("Please enter a valid URL starting with http:// or https://");
      setLoading(false);
      return;
    }
    
    try {
      const res = await axiosInstance.post("/url/scan", { url }, {
        withCredentials: true,
      });
      
      setResult(res.data);
      setShowScanForm(true); // Show scan form instead of changing value
      toast.success("Scan completed successfully!");
      
      // Clear URL input
      setUrl("");
      
    } catch (err) {
      console.error("Scan error:", err);
      setResult({ error: "Scan failed" });
      setShowScanForm(true); // Still show form with error
      toast.error("Scan failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleBackToDashboard = () => {
    setShowScanForm(false);
    setResult(null);
    setUrl("");
  };

  const sidebarItems = [
    {
      label: "Dashboard",
      icon: <LayoutDashboard className="h-6 w-6" />,
      onClick: () => {
        handleBackToDashboard();
      },
    },
    {
      label: "Scan",
      icon: <Globe className="h-6 w-6" />,
      onClick: () => navigate("/scan"),
    },
    {
      label: "Reports",
      icon: <Bug className="h-6 w-6" />,
      onClick: () => navigate("/reports"),
    },
    {
      label: "Profile",
      icon: <User className="h-6 w-6" />,
      onClick: () => navigate("/profile"),
    },
    {
      label: "Sign Out",
      icon: <LogOut className="h-5 w-5" />,
      onClick: handleSignOut,
    },
  ];

  function OverviewItem({
    title,
    value,
    bold,
  }: {
    title: string;
    value: string | number;
    bold?: boolean;
  }) {
    return (
      <div className="bg-[#1c1f26] p-6 rounded-lg shadow-md hover:bg-[#272b32] transition-colors flex justify-between items-center">
        <p className="text-gray-100">{title}</p>
        <p className={`text-white ${bold ? "font-bold" : ""}`}>{value}</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0f1115]">
        <LoaderCircle className="animate-spin w-12 h-12 text-blue-500" />
      </div>
    );
  }

  // Show scan form if we have results
  if (showScanForm && result) {
    return (
      <div className="bg-[#0f1115] text-white">
        <ScanForm resultValue={result} />
        {/* Add a back button that calls our handler */}
        <div className="fixed top-20 left-4 z-50">
          <button
            onClick={handleBackToDashboard}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors shadow-lg"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f1115] text-white flex overflow-hidden relative">
      <div className="absolute top-4 left-4 md:hidden z-50">
        <Menu
          className="w-7 h-7 cursor-pointer"
          onClick={() => setSidebarOpen(true)}
        />
      </div>

      <aside
        className={`bg-[#1c1f26] fixed top-0 px-2 left-0 h-screen z-50 w-[250px] border-r border-gray-700 transition-transform duration-300 ease-in-out ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        } md:translate-x-0 md:relative md:block`}
      >
        <div className="flex items-center justify-between p-4">
          <div className="flex items-center gap-2">
            <img src={logo} alt="logo" className="w-8 h-8" />
            <h1 className="text-xl font-bold">CyberSecure-web</h1>
          </div>
          <X
            className="w-6 h-6 cursor-pointer md:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        </div>
        <ul className="mt-4">
          {sidebarItems.map((item) => (
            <li
              key={item.label}
              className="flex items-center gap-2 p-4 rounded-xl hover:bg-gray-800 cursor-pointer transition-colors"
              onClick={() => {
                item.onClick();
                setSidebarOpen(false);
              }}
            >
              {item.icon}
              {item.label}
            </li>
          ))}
        </ul>
      </aside>

      <main className="flex-1 p-4 w-full overflow-x-hidden">
        <div className="w-full max-w-[75rem] mx-auto">
          <div className="flex justify-between items-center mb-4">
            <h1 className="text-4xl font-bold">Dashboard</h1>
            <User
              className="w-6 h-6 text-white cursor-pointer hover:text-blue-400 transition-colors"
              onClick={() => navigate("/profile")}
            />
          </div>

          <div className="bg-[#1c1f26] rounded-xl p-4 shadow-lg w-full mb-6">
            <h2 className="md:text-3xl text-xl font-semibold pb-2">
              Website Scan Overview
            </h2>
            <hr className="text-gray-500 mb-4" />
            <div className="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <OverviewItem title="Total Scans" value={reports?.length || 0} bold />
              <OverviewItem title="Phishing Pages" value={0} />
              <OverviewItem title="Malware" value={0} />
              <OverviewItem title="Completed Scans" value={reports?.length || 0} />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-[#1c1f26] p-6 rounded-lg shadow-md">
              <h2 className="text-xl font-semibold mb-4">Quick Scan</h2>
              <form onSubmit={handleScan}>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter Website URL (e.g., https://example.com)"
                  className="w-full p-3 rounded bg-gray-800 text-white border border-gray-600 mb-4 focus:border-blue-500 focus:outline-none"
                  required
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white px-4 py-2 rounded w-full transition-colors"
                >
                  {loading ? "Scanning..." : "Scan Now"}
                </button>
              </form>
            </div>

            <div className="bg-[#1c1f26] p-6 rounded-lg shadow-md">
              <h2 className="text-xl font-semibold mb-4">Security Tips</h2>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>Keep your software updated</li>
                <li>Use strong, unique passwords</li>
                <li>Enable two-factor authentication</li>
                <li>Regularly back up your data</li>
                <li>Be cautious with email attachments</li>
              </ul>
            </div>
          </div>

          {/* Recent Reports */}
          {reports.length > 0 && (
            <div className="bg-[#1c1f26] rounded-xl p-6 shadow-lg w-full mt-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Recent Scans</h2>
                <button
                  onClick={() => navigate("/reports")}
                  className="text-blue-400 hover:text-blue-300 text-sm"
                >
                  View All
                </button>
              </div>
              <div className="space-y-3">
                {reports.slice(0, 3).map((report) => (
                  <div
                    key={report._id}
                    className="flex justify-between items-center p-3 bg-gray-800 rounded-lg"
                  >
                    <div>
                      <p className="text-white font-medium truncate">{report.domain}</p>
                      <p className="text-gray-400 text-sm">
                        {new Date(report.createdAt).toLocaleDateString()}
                      </p>
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
        </div>
      </main>
    </div>
  );
};

export default Dashboard;