import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import banner from "../assets/signin_banner.png";
import google from "../assets/google.png";
import lbanner from "../assets/login_banner.png";
import logo from "../../public/assets/Logo.svg";
import eye from "../assets/eye.png";
import { toast } from "react-toastify";
import { axiosInstance } from "../utility/baseUrl";
import { useAuth } from "../context/Authcontext";

interface UserData {
  email: string;
  password: string;
}

const handleGoogleAuth = () => {
  // Update this URL to match your backend Google OAuth endpoint
  window.location.href = `${import.meta.env.VITE_API_URL || "http://localhost:5000"}/auth/google`;
};

export default function SignIn() {
  const [userData, setUserData] = useState<UserData>({
    email: "",
    password: "",
  });
  const [visible, setVisible] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const { setUser, isAuthenticated } = useAuth();

  const navigate = useNavigate();

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard");
    }
  }, [isAuthenticated, navigate]);

  const validateForm = (): boolean => {
    if (!userData.email.trim()) {
      toast.error("Please enter your email");
      return false;
    }
    
    if (!userData.password.trim()) {
      toast.error("Please enter your password");
      return false;
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      toast.error("Please enter a valid email address");
      return false;
    }

    return true;
  };

  const handleSignIn = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    
    if (!validateForm()) return;

    setLoading(true);
    try {
      const res = await axiosInstance.post("/user/signin", userData, {
        withCredentials: true,
      });
      
      if (res.status === 200) {
        toast.success("Sign in successful");
        setUser(res.data.user.id);
        navigate("/dashboard");
      }
    } catch (error: any) {
      console.error("Sign in error:", error);
      
      if (error.response?.status === 401) {
        toast.error("Invalid email or password");
      } else if (error.response?.status === 404) {
        toast.error("Account not found. Please sign up first.");
      } else {
        toast.error("Sign in failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: keyof UserData, value: string) => {
    setUserData(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div className="flex items-center justify-center bg-[#0f1115] min-h-screen md:flex-row flex-col-reverse shadow-lg">
      {/* Left Side - Banner */}
      <div className="relative w-full md:w-[500px]">
        <img
          src={banner}
          alt="Sign in banner"
          className="md:w-full md:rounded-tl-3xl rounded-bl-3xl rounded-br-3xl md:rounded-bl-none md:rounded-br-none shadow-lg relative z-0"
        />
        <img
          src={lbanner}
          alt="Banner logo"
          className="absolute bottom-20 p-5 md:p-10 left-0 z-10"
        />
        <div className="p-3 md:p-0">
          <img
            src={logo}
            alt="CyberCage logo"
            className="absolute top-0 p-5 pl-12 md:p-10 left-10 z-10"
          />
          <h1 className="absolute top-3 p-5 md:p-10 right-10 md:right-28 z-10 text-3xl md:text-4xl pr-10 text-white font-bold">
            CyberSecure-web
          </h1>
        </div>
        <div>
          <h1 className="hidden md:block font-semibold text-white text-lg md:text-xl p-10 md:p-20 absolute bottom-2 left-5 md:left-9">
            Online Community For Secure
          </h1>
          <p className="text-[#f5f5f571] absolute left-5 md:left-9 bottom-6 md:bottom-0 text-sm md:text-base pr-5 md:pr-0 pb-2">
            "Modern cyber attacks don't always break the door — they wait for
            you to open it. Stay ahead with smart scanning."
          </p>
        </div>
      </div>

      {/* Right Side - Form */}
      <div className="flex flex-col py-10 md:py-30 pt-10 md:pt-20 justify-center w-full md:w-[500px] bg-white shadow-lg px-6 md:px-10 md:rounded-br-2xl">
        <h1 className="font-bold text-center md:text-2xl text-3xl mb-6">
          Welcome back to CyberSecure-web
        </h1>

        <button
          onClick={handleGoogleAuth}
          type="button"
          className="flex items-center cursor-pointer mb-6 justify-center gap-2 h-12 text-white bg-[#FAFAFA] rounded-lg hover:bg-blue-50 transition-colors border border-gray-300"
        >
          <img src={google} alt="Google" className="w-6 md:w-8" />
          <span className="text-gray-700 text-sm md:text-base font-medium">
            Sign In with Google
          </span>
        </button>

        <div className="relative mb-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or continue with email</span>
          </div>
        </div>

        <form onSubmit={handleSignIn} className="flex flex-col">
          <div className="flex justify-between items-center">
            <label className="ml-2 text-sm md:text-base font-medium">Email</label>
          </div>
          <input
            type="email"
            className="w-full h-12 mb-6 outline-0 border-b-2 border-[#BDBDBD] focus:border-blue-500 transition-colors px-2"
            placeholder="Enter your email"
            value={userData.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            required
          />
          
          <div className="flex justify-between items-center">
            <label className="ml-2 text-sm md:text-base font-medium">Password</label>
            <button
              type="button"
              onClick={() => setVisible(!visible)}
              className="p-1"
            >
              <img
                src={eye}
                alt="Toggle password visibility"
                className="cursor-pointer w-5 h-5 opacity-70 hover:opacity-100 transition-opacity"
              />
            </button>
          </div>

          <input
            type={visible ? "text" : "password"}
            className="w-full h-12 mb-6 outline-0 border-b-2 border-[#BDBDBD] focus:border-blue-500 transition-colors px-2"
            placeholder="Enter your password"
            value={userData.password}
            onChange={(e) => handleInputChange('password', e.target.value)}
            required
          />

          <button
            type="submit"
            disabled={loading}
            className="w-full h-12 mt-4 text-white bg-[#3F51B5] rounded-lg hover:bg-[#3949AB] disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
          >
            {loading ? "Signing In..." : "Sign In"}
          </button>
        </form>

        <p className="text-center mt-6 text-sm md:text-base">
          No Account Yet?
          <button
            onClick={() => navigate("/signup")}
            className="text-blue-600 hover:text-blue-700 cursor-pointer ml-1 font-medium underline"
          >
            Sign Up
          </button>
        </p>

        <p className="text-center mt-2 text-sm">
          <button
            onClick={() => navigate("/")}
            className="text-gray-600 hover:text-gray-700 cursor-pointer font-medium"
          >
            Back to Home
          </button>
        </p>
      </div>
    </div>
  );
}