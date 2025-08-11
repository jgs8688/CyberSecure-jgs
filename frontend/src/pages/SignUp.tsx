import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import banner from "../assets/banner_bg.png";
import google from "../assets/google.png";
import lbanner from "../assets/login_banner.png";
import logo from "../../public/assets/Logo.svg";
import eye from "../assets/eye.png";
import { axiosInstance } from "../utility/baseUrl";
import { toast } from "react-toastify";
import { useAuth } from "../context/Authcontext";

interface UserData {
  username: string;
  email: string;
  password: string;
}

export default function SignUp() {
  const [userdata, setUserData] = useState<UserData>({
    username: "",
    email: "",
    password: "",
  });
  const [visible, setVisible] = useState<boolean>(false);
  const [emailVerified, setEmailVerified] = useState<boolean>(false);
  const [otp, setOtp] = useState<string>("");
  const [otpSent, setOtpSent] = useState<boolean>(false); // New state to track if OTP was sent
  const [agree, setAgree] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [otpLoading, setOtpLoading] = useState<boolean>(false);

  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate("/dashboard");
    }
  }, [isAuthenticated, navigate]);

  const validateSignup = (): boolean => {
    if (userdata.username.trim() === "") {
      toast.error("Please enter a username");
      return false;
    }

    if (userdata.username.length < 3) {
      toast.error("Username must be at least 3 characters long");
      return false;
    }

    if (userdata.email.trim() === "") {
      toast.error("Please enter an email");
      return false;
    }

    if (!emailVerified) {
      toast.error("Please verify your email");
      return false;
    }

    if (userdata.password.trim() === "") {
      toast.error("Please enter a password");
      return false;
    }

    if (!passwordRegex.test(userdata.password)) {
      toast.error(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character"
      );
      return false;
    }

    if (!agree) {
      toast.error("Please agree to the terms and conditions");
      return false;
    }

    return true;
  };

  const handleSignup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    
    if (!validateSignup()) return;

    setLoading(true);
    try {
      const res = await axiosInstance.post("/user/signup", userdata);
      
      if (res.status === 201) {
        toast.success("Sign up successful! Please sign in to continue.");
        setUserData({ username: "", email: "", password: "" });
        setEmailVerified(false);
        setOtpSent(false);
        setOtp("");
        setAgree(false);
        navigate("/signin");
      }
    } catch (error: any) {
      console.error("Error signing up:", error);
      
      if (error.response?.status === 400) {
        toast.error("User already exists with this email");
      } else if (error.response?.status === 409) {
        toast.error("Username or email already taken");
      } else {
        toast.error("Sign up failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const verifyEmail = async (e: React.FormEvent) => {
    e.preventDefault();

    if (userdata.username.trim() === "") {
      toast.error("Please enter a username");
      return;
    }

    if (userdata.username.length < 3) {
      toast.error("Username must be at least 3 characters long");
      return;
    }

    const email = userdata.email.trim();
    if (email === "") {
      toast.error("Please enter an email");
      return;
    }

    if (!emailRegex.test(email)) {
      toast.error("Please enter a valid email");
      return;
    }

    setOtpLoading(true);
    try {
      const res = await axiosInstance.post("/mail/otp-send", { email });
      
      if (res.status === 200) {
        toast.success("Verification code sent to your email");
        setOtpSent(true);
        setOtp(""); // Clear any existing OTP
      }
    } catch (error: any) {
      console.error("Error verifying email:", error);
      
      if (error.response?.status === 400) {
        toast.error("Email already exists");
      } else {
        toast.error("Failed to send verification email. Please try again.");
      }
    } finally {
      setOtpLoading(false);
    }
  };

  const verifyOtp = async (otpValue: string) => {
    if (otpValue.length !== 6) {
      toast.error("Please enter a valid 6-digit OTP");
      return;
    }

    try {
      const res = await axiosInstance.post("/mail/verify-otp", { 
        otp: otpValue,
        email: userdata.email 
      });

      if (res.status === 200) {
        setOtpSent(false);
        setOtp("");
        setEmailVerified(true);
        toast.success("Email verified successfully");
      }
    } catch (error: any) {
      console.error("Error verifying OTP:", error);
      
      if (error.response?.status === 400) {
        toast.error("Invalid or expired OTP");
      } else if (error.response?.status === 404) {
        toast.error("OTP not found. Please request a new one.");
      } else {
        toast.error("OTP verification failed. Please try again.");
      }
    }
  };

  const handleGoogleSignUp = () => {
    window.location.href = `${import.meta.env.VITE_API_URL || "http://localhost:5000"}/auth/google`;
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
          alt="Sign up banner"
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
            "Security is not a luxury anymore — it's a necessity. Make your
            websites stronger with our free, powerful vulnerability scanner"
          </p>
        </div>
      </div>

      {/* Right Side - Form */}
      <div className="flex flex-col pt-10 md:pt-20 justify-center w-full md:w-[500px] bg-white shadow-lg px-6 md:px-10 md:rounded-br-2xl">
        <h1 className="font-bold text-center md:text-2xl text-3xl mb-6">
          Join & Connect with CyberSecure-web
        </h1>

        <button
          onClick={handleGoogleSignUp}
          type="button"
          className="flex items-center cursor-pointer mb-6 justify-center gap-2 h-12 text-white bg-[#FAFAFA] rounded-lg hover:bg-blue-50 transition-colors border border-gray-300"
        >
          <img src={google} alt="Google" className="w-6 md:w-8" />
          <span className="text-gray-700 text-sm md:text-base font-medium">
            Sign up with Google
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

        <form onSubmit={handleSignup}>
          <label className="ml-2 text-sm md:text-base font-medium">Username</label>
          <input
            type="text"
            className="w-full h-12 mb-6 outline-0 border-b-2 border-[#BDBDBD] focus:border-blue-500 transition-colors px-2"
            placeholder="Enter your username"
            value={userdata.username}
            onChange={(e) => handleInputChange('username', e.target.value)}
            required
            minLength={3}
          />

          <div className="flex justify-between items-center">
            <label className="ml-2 text-sm md:text-base font-medium">Email</label>
            <button
              type="button"
              onClick={verifyEmail}
              disabled={otpLoading || emailVerified}
              className={`text-sm md:text-base cursor-pointer font-medium ${
                emailVerified 
                  ? 'text-green-600' 
                  : otpLoading 
                    ? 'text-gray-400' 
                    : 'text-blue-600 hover:text-blue-700'
              } transition-colors`}
            >
              {emailVerified ? "✓ Verified" : otpLoading ? "Sending..." : otpSent ? "Resend OTP" : "Verify Email"}
            </button>
          </div>
          <input
            type="email"
            className="w-full h-12 mb-6 outline-0 border-b-2 border-[#BDBDBD] focus:border-blue-500 transition-colors px-2"
            placeholder="Enter your email"
            value={userdata.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            required
            disabled={emailVerified}
          />

          {otpSent && !emailVerified && (
            <div className="mb-6">
              <label className="ml-2 text-sm md:text-base text-red-600 font-medium">
                Enter 6-digit verification code
              </label>
              <input
                type="text"
                className="w-full h-12 outline-0 border-b-2 border-red-400 focus:border-red-600 transition-colors px-2"
                placeholder="Enter OTP"
                maxLength={6}
                value={otp}
                onChange={(e) => {
                  const value = e.target.value; // allow letters + numbers
                  setOtp(value);
                  if (value.length === 6) {
                    verifyOtp(value);
                  }
                }}
              />
              <p className="text-xs text-gray-500 mt-1">
                Check your email for the verification code
              </p>
            </div>
          )}

          {!otpSent && emailVerified && (
            <div className="mb-6">
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
                className="w-full h-12 outline-0 border-b-2 border-[#BDBDBD] focus:border-blue-500 transition-colors px-2"
                placeholder="Enter your password"
                value={userdata.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                required
              />
              <p className="text-xs text-gray-500 mt-1">
                Password must be at least 8 characters with uppercase, lowercase, number, and special character
              </p>
            </div>
          )}
        </form>

        {!otpSent && emailVerified && (
          <div className="flex items-center justify-center text-sm md:text-base mb-6">
            <input
              type="checkbox"
              checked={agree}
              onChange={(e) => setAgree(e.target.checked)}
              className="cursor-pointer mr-2"
              required
            />
            <label className="cursor-pointer">
              I agree to the{" "}
              <span className="text-blue-600 hover:text-blue-700 underline">
                terms and conditions
              </span>
            </label>
          </div>
        )}

        <button
          type="button"
          onClick={handleSignup}
          disabled={loading || otpSent || !emailVerified}
          className="w-full h-12 mt-4 text-white bg-[#3F51B5] rounded-lg hover:bg-[#3949AB] disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
        >
          {loading ? "Creating Account..." : "Sign Up"}
        </button>

        <p className="text-center mt-6 text-sm md:text-base">
          Already have an Account?
          <button
            onClick={() => navigate("/signin")}
            className="text-blue-600 hover:text-blue-700 cursor-pointer ml-1 font-medium underline"
          >
            Sign In
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