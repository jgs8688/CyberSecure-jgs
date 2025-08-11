import React, { createContext, useState, useContext, useEffect } from "react";
import type { ReactNode } from "react";

// Define types for the context values
interface AuthContextType {
  user: string | null;
  setUser: (newUser: string | null) => void;
  scanResult: any;
  setScanResult: React.Dispatch<React.SetStateAction<any>>;
  totalSans: number;
  setTotalSans: React.Dispatch<React.SetStateAction<number>>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<any>(null);
  const [totalSans, setTotalSans] = useState<number>(0);

  // Derived state for authentication status
  const isAuthenticated = user !== null;

  // Load user from localStorage on mount (if you want persistence)
  useEffect(() => {
    const savedUser = localStorage.getItem('cybercage_user');
    if (savedUser) {
      try {
        setUser(savedUser);
      } catch (error) {
        console.error('Error loading user from localStorage:', error);
        localStorage.removeItem('cybercage_user');
      }
    }
  }, []);

  // Save user to localStorage when it changes
  useEffect(() => {
    if (user) {
      localStorage.setItem('cybercage_user', user);
    } else {
      localStorage.removeItem('cybercage_user');
    }
  }, [user]);

  // Enhanced setUser function that also clears related data on logout
  const enhancedSetUser = (newUser: string | null) => {
    setUser(newUser);
    if (!newUser) {
      // Clear all user-related data on logout
      setScanResult(null);
      setTotalSans(0);
    }
  };

  const contextValue: AuthContextType = {
    user,
    setUser: enhancedSetUser, // Now this references the function defined above
    scanResult,
    setScanResult,
    totalSans,
    setTotalSans,
    isAuthenticated,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to access the auth context
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

// Optional: Hook for checking if user is authenticated
export const useRequireAuth = () => {
  const { isAuthenticated, user } = useAuth();
  
  useEffect(() => {
    if (!isAuthenticated) {
      // You could redirect here if needed
      console.warn('User is not authenticated');
    }
  }, [isAuthenticated]);

  return { isAuthenticated, user };
};