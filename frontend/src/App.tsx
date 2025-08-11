import SignUp from "./pages/SignUp";
import SignIn from "./pages/SignIn";
import { Route, Routes } from "react-router-dom";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { useAuth } from "./context/Authcontext";
import { useEffect, useState } from "react";
import { axiosInstance } from "./utility/baseUrl";
import Dashboard from "./components/Dashboard";
import Home from "./pages/Home";
import Report from "./pages/Report";
import ScanForm from "./components/ScanForm";
import UserProfile from "./components/UserProfile";
import NotFound from "./components/NotFound";
import { LoaderCircle } from "lucide-react";

interface ReportItem {
  name: string;
  domain: string;
  pdf: string;
}

export default function App() {
  const { user, setUser, scanResult, totalSans, setTotalSans } = useAuth();
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<ReportItem[]>([]);

  useEffect(() => {
    const authData = async () => {
      try {
        const res = await axiosInstance.get("/user/authorized", {
          withCredentials: true,
        });

        if (res.status === 200) {
          setUser(res.data.user.id);
        } else {
          setUser(null);
        }
      } catch (error) {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    authData();
  }, [setUser]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0f1115]">
        <LoaderCircle className="animate-spin w-12 h-12 text-blue-500" />
      </div>
    );
  }

  return (
    <div className="bg-[#0f1115] min-h-screen">
      <Routes>
        {/* Public routes */}
        <Route path="/" element={!user ? <Home /> : <Dashboard />} />
        <Route path="/home" element={<Home />} />
        <Route 
          path="/signup" 
          element={!user ? <SignUp /> : <Dashboard />} 
        />
        <Route 
          path="/signin" 
          element={!user ? <SignIn /> : <Dashboard />} 
        />

        {/* Protected routes */}
        <Route 
          path="/dashboard" 
          element={user ? <Dashboard /> : <SignIn />} 
        />
        <Route 
          path="/scan" 
          element={user ? <Dashboard /> : <SignIn />} // Redirect scan to dashboard
        />
        <Route 
          path="/reports" 
          element={user ? <Report /> : <SignIn />} 
        />
        <Route 
          path="/profile" 
          element={user ? <UserProfile /> : <SignIn />} 
        />

        {/* Legacy routes for backward compatibility - redirect to dashboard */}
        <Route 
          path="/ScanForm" 
          element={user ? <Dashboard /> : <SignIn />} 
        />
        <Route 
          path="/report" 
          element={user ? <Report /> : <SignIn />} 
        />
        <Route 
          path="/userProfile" 
          element={user ? <UserProfile /> : <SignIn />} 
        />

        {/* 404 fallback */}
        <Route path="*" element={<NotFound />} />
      </Routes>

      <ToastContainer 
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />
    </div>
  );
}