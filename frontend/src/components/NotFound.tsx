import React from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeftCircle, Home, Shield } from "lucide-react";
import { useAuth } from "../context/Authcontext";

const NotFound: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  const handleGoHome = () => {
    navigate("/");
  };

  const handleGoToDashboard = () => {
    navigate("/dashboard");
  };

  const handleGoBack = () => {
    window.history.back();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-[#0f1115] via-[#1c1f26] to-[#111418] px-6">
      <div className="text-center max-w-lg">
        {/* 404 Number */}
        <div className="relative mb-8">
          <h1 className="text-8xl md:text-9xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-600 select-none">
            404
          </h1>
          <div className="absolute inset-0 text-8xl md:text-9xl font-bold text-blue-500 opacity-20 blur-sm">
            404
          </div>
        </div>

        {/* Error Message */}
        <div className="mb-8">
          <h2 className="text-2xl md:text-3xl text-white font-semibold mb-4">
            Oops! Page not found.
          </h2>
          <p className="text-gray-400 text-lg leading-relaxed">
            The page you're looking for doesn't exist or has been moved.
            Don't worry, even the best security systems have their blind spots!
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <button
            onClick={handleGoBack}
            className="inline-flex items-center px-6 py-3 bg-gray-600 hover:bg-gray-700 text-white text-lg font-medium rounded-full transition-colors"
          >
            <ArrowLeftCircle className="w-5 h-5 mr-2" />
            Go Back
          </button>

          <button
            onClick={handleGoHome}
            className="inline-flex items-center px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white text-lg font-medium rounded-full transition-colors"
          >
            <Home className="w-5 h-5 mr-2" />
            Home
          </button>

          {isAuthenticated && (
            <button
              onClick={handleGoToDashboard}
              className="inline-flex items-center px-6 py-3 bg-green-600 hover:bg-green-700 text-white text-lg font-medium rounded-full transition-colors"
            >
              <Shield className="w-5 h-5 mr-2" />
              Dashboard
            </button>
          )}
        </div>

        {/* Helpful Links */}
        <div className="mt-12 pt-8 border-t border-gray-700">
          <p className="text-gray-500 mb-4">Looking for something specific?</p>
          <div className="flex flex-wrap justify-center gap-4 text-sm">
            <button
              onClick={() => navigate("/")}
              className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
            >
              Home
            </button>
            {isAuthenticated ? (
              <>
                <button
                  onClick={() => navigate("/dashboard")}
                  className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                >
                  Dashboard
                </button>
                <button
                  onClick={() => navigate("/reports")}
                  className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                >
                  Reports
                </button>
                <button
                  onClick={() => navigate("/profile")}
                  className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                >
                  Profile
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => navigate("/signin")}
                  className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                >
                  Sign In
                </button>
                <button
                  onClick={() => navigate("/signup")}
                  className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                >
                  Sign Up
                </button>
              </>
            )}
          </div>
        </div>

        {/* Fun Security Message */}
        <div className="mt-8 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
          <p className="text-gray-400 text-sm italic">
            "In cybersecurity, getting lost is just another way of exploring potential vulnerabilities. 
            But this time, let's navigate back to safety!" 🔒
          </p>
        </div>
      </div>
    </div>
  );
};

export default NotFound;