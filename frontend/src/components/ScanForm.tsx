import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import ReportDetails from "./ReportDetails";
import { useAuth } from "../context/Authcontext";
import { ArrowLeft, Home } from "lucide-react";
import logo from "../../public/assets/Logo.svg";

interface resultData {
  resultValue: any;
}

const ScanForm: React.FC<resultData> = ({ resultValue }) => {
  const navigate = useNavigate();
  const { user } = useAuth();

  console.log("Scan Result Data: ", resultValue);

  const handleBackToDashboard = (e: React.MouseEvent) => {
    e.preventDefault();
    console.log("Navigating to dashboard..."); 
    
    // Force navigation with window.location if navigate doesn't work
    try {
      navigate("/dashboard", { replace: true });
      
      // Fallback after small delay
      setTimeout(() => {
        if (window.location.pathname !== "/dashboard") {
          window.location.href = "/dashboard";
        }
      }, 100);
    } catch (error) {
      console.error("Navigation error:", error);
      window.location.href = "/dashboard";
    }
  };

  const handleGoHome = (e: React.MouseEvent) => {
    e.preventDefault();
    console.log("Navigating to home..."); 
    
    try {
      navigate("/", { replace: true });
      
      // Fallback after small delay
      setTimeout(() => {
        if (window.location.pathname !== "/") {
          window.location.href = "/";
        }
      }, 100);
    } catch (error) {
      console.error("Navigation error:", error);
      window.location.href = "/";
    }
  };

  return (
    <div className="bg-[#0f1116] w-full min-h-screen overflow-x-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-700 bg-[#0f1116]">
        <div className="flex items-center gap-2 flex-shrink-0">
          <img src={logo} alt="Logo" className="w-8 h-8" />
          <h1 className="text-white font-bold text-xl sm:text-2xl truncate">CyberSecure-web</h1>
        </div>
        
        <div className="flex items-center gap-2 sm:gap-4 flex-shrink-0">
          <button
            onClick={handleBackToDashboard}
            className="flex items-center gap-1 sm:gap-2 px-2 sm:px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm sm:text-base whitespace-nowrap"
            type="button"
          >
            <ArrowLeft className="w-4 h-4" />
            <span className="hidden sm:inline">Back to Dashboard</span>
            <span className="sm:hidden">Dashboard</span>
          </button>
          
          <button
            onClick={handleGoHome}
            className="flex items-center gap-1 sm:gap-2 px-2 sm:px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors text-sm sm:text-base whitespace-nowrap"
            type="button"
          >
            <Home className="w-4 h-4" />
            <span className="hidden sm:inline">Home</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center justify-start p-4 sm:p-6 bg-[#0f1116] min-h-[calc(100vh-80px)]">
        <div className="w-full max-w-6xl">
          <div className="text-center mb-6 sm:mb-8">
            <h1 className="text-white font-bold text-3xl sm:text-4xl lg:text-5xl mb-4 break-words">
              Scan Results
            </h1>
            
            {/* Report Name with proper text wrapping */}
            <div className="mb-4 px-2">
              <h3 className="text-[#a1a1aa] font-semibold text-lg sm:text-xl break-words word-wrap overflow-wrap-anywhere max-w-full">
                {resultValue?.name || resultValue?.domain || "Scan completed"}
              </h3>
            </div>
            
            {/* Status Badge */}
            <div className="inline-block">
              {resultValue?.error ? (
                <div className="text-white bg-red-600 font-semibold px-4 py-2 rounded-lg">
                  Scan Failed
                </div>
              ) : (
                <div className="text-[#b1b1bb] bg-[#10b98136] font-semibold px-4 py-2 rounded-lg">
                  Scan Completed Successfully
                </div>
              )}
            </div>
          </div>

          {/* Results Section */}
          <div className="w-full bg-[#0f1116]">
            {resultValue?.error ? (
              <div className="text-center text-red-500 mt-10 p-6 sm:p-8 bg-[#1c1f26] rounded-xl mx-2 sm:mx-0">
                <h2 className="text-xl sm:text-2xl font-bold mb-4">Scan Failed</h2>
                <p className="text-base sm:text-lg mb-4 break-words">
                  {resultValue.error || "An error occurred during the scan"}
                </p>
                <button
                  onClick={handleBackToDashboard}
                  className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  type="button"
                >
                  Try Again
                </button>
              </div>
            ) : resultValue ? (
              <div className="bg-[#0f1116] w-full overflow-x-auto">
                <ReportDetails data={resultValue} />
                
                {/* Back to Dashboard Button at Bottom */}
                <div className="text-center mt-8 mb-6">
                  <button
                    onClick={handleBackToDashboard}
                    className="px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-semibold"
                    type="button"
                  >
                    ← Back to Dashboard
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400 mt-10 p-6 sm:p-8 bg-[#1c1f26] rounded-xl mx-2 sm:mx-0">
                <h2 className="text-xl sm:text-2xl font-bold mb-4">No Scan Data</h2>
                <p className="text-base sm:text-lg mb-4">
                  No scan results available. Please start a new scan.
                </p>
                <button
                  onClick={handleBackToDashboard}
                  className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  type="button"
                >
                  Start New Scan
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanForm;