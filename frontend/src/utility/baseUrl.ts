import axios from "axios";

const baseUrl = import.meta.env.VITE_API_URL || "http://localhost:5000";
const axiosInstance = axios.create({
  baseURL: baseUrl,
  headers: {
    "Content-Type": "application/json",
  },
});

export {
    axiosInstance,
}