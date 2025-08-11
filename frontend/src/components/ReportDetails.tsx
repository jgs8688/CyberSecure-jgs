import React from "react";
import { ExternalLink, AlertTriangle, CheckCircle, XCircle } from "lucide-react";

interface reportData {
  data: any;
}

const ReportDetails: React.FC<reportData> = ({ data }) => {
  if (!data || !data.report) {
    return (
      <div className="text-center text-red-500 mt-10 p-8 bg-[#1c1f26] rounded-xl">
        <XCircle className="w-16 h-16 mx-auto mb-4" />
        <h2 className="text-2xl font-bold mb-2">Report Not Found</h2>
        <p className="text-lg">Report data is invalid or unavailable.</p>
      </div>
    );
  }

  const { report } = data;

  const getStatusIcon = (isFound: boolean, isVulnerable: boolean = false) => {
    if (isFound || isVulnerable) {
      return <XCircle className="w-5 h-5 text-red-500" />;
    }
    return <CheckCircle className="w-5 h-5 text-green-500" />;
  };

  const getStatusColor = (isFound: boolean, isVulnerable: boolean = false) => {
    if (isFound || isVulnerable) {
      return "text-red-500";
    }
    return "text-green-500";
  };

  const getStatusText = (isFound: boolean, label?: string) => {
    return isFound ? (label || "Found") : "Not Found";
  };

  const securityItems = [
    {
      category: "Malware",
      status: report?.malware?.found,
      statusText: getStatusText(report?.malware?.found),
      details: report?.malware?.links?.length > 0
        ? report.malware.links.join(", ")
        : "No malicious links detected",
      icon: getStatusIcon(report?.malware?.found),
      colorClass: getStatusColor(report?.malware?.found),
    },
    {
      category: "Phishing",
      status: report?.phishing?.found,
      statusText: getStatusText(report?.phishing?.found),
      details: report?.phishing?.found
        ? "Potential phishing indicators detected. Review login forms and secure authentication."
        : "No phishing indicators found",
      icon: getStatusIcon(report?.phishing?.found),
      colorClass: getStatusColor(report?.phishing?.found),
    },
    {
      category: "Open Redirects",
      status: report?.openRedirects?.found,
      statusText: getStatusText(report?.openRedirects?.found),
      details: report?.openRedirects?.found
        ? "Open redirect vulnerabilities detected. Validate redirect URLs server-side."
        : "No open redirect vulnerabilities found",
      icon: getStatusIcon(report?.openRedirects?.found),
      colorClass: getStatusColor(report?.openRedirects?.found),
    },
    {
      category: "CMS Detection",
      status: !!report?.cms?.cms,
      statusText: report?.cms?.cms || "Not Detected",
      details: report?.cms?.vulnerable 
        ? "CMS vulnerabilities detected. Update to latest version."
        : report?.cms?.cms 
          ? "CMS detected and appears secure"
          : "No CMS detected",
      icon: report?.cms?.vulnerable 
        ? <AlertTriangle className="w-5 h-5 text-yellow-500" />
        : report?.cms?.cms 
          ? <CheckCircle className="w-5 h-5 text-blue-500" />
          : <CheckCircle className="w-5 h-5 text-gray-500" />,
      colorClass: report?.cms?.vulnerable 
        ? "text-yellow-500" 
        : report?.cms?.cms 
          ? "text-blue-500"
          : "text-gray-500",
    },
    {
      category: "Security Headers",
      status: report?.securityHeaders?.missing?.length > 0,
      statusText: report?.securityHeaders?.missing?.length === 0 ? "All Present" : "Missing Headers",
      details: report?.securityHeaders?.missing?.length > 0 
        ? `Missing: ${report.securityHeaders.missing.join(", ")}`
        : "All essential security headers are present",
      icon: getStatusIcon(report?.securityHeaders?.missing?.length > 0),
      colorClass: getStatusColor(report?.securityHeaders?.missing?.length > 0),
    },
    {
      category: "Open Ports",
      status: report?.openPorts?.found,
      statusText: getStatusText(report?.openPorts?.found),
      details: report?.openPorts?.openPorts?.length > 0
        ? `Open ports: ${report.openPorts.openPorts.join(", ")}`
        : "No unnecessary open ports detected",
      icon: getStatusIcon(report?.openPorts?.found),
      colorClass: getStatusColor(report?.openPorts?.found),
    },
    {
      category: "Hidden Scripts",
      status: report?.hiddenScripts?.found,
      statusText: getStatusText(report?.hiddenScripts?.found),
      details: report?.hiddenScripts?.samples?.length > 0
        ? `Detected scripts: ${report.hiddenScripts.samples.slice(0, 2).join(", ")}${report.hiddenScripts.samples.length > 2 ? '...' : ''}`
        : "No hidden or suspicious scripts found",
      icon: getStatusIcon(report?.hiddenScripts?.found),
      colorClass: getStatusColor(report?.hiddenScripts?.found),
    },
    {
      category: "DNS Rebinding",
      status: report?.dnsRebinding?.found,
      statusText: getStatusText(report?.dnsRebinding?.found),
      details: report?.dnsRebinding?.records?.length > 0
        ? `Suspicious records: ${report.dnsRebinding.records.join(", ")}`
        : "No DNS rebinding vulnerabilities detected",
      icon: getStatusIcon(report?.dnsRebinding?.found),
      colorClass: getStatusColor(report?.dnsRebinding?.found),
    },
  ];

  const threatCount = securityItems.filter(item => 
    item.category !== "CMS Detection" && item.status
  ).length;

  return (
    <div className="mx-auto p-6 bg-[#0f1116] shadow-lg rounded-xl mt-8 max-w-7xl">
      {/* Summary Card */}
      <div className="mb-6 p-6 bg-[#1c1f26] rounded-xl border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-white">Security Scan Summary</h2>
          <div className={`flex items-center gap-2 px-4 py-2 rounded-full ${
            threatCount === 0 
              ? 'bg-green-900/50 text-green-400' 
              : 'bg-red-900/50 text-red-400'
          }`}>
            {threatCount === 0 ? (
              <CheckCircle className="w-5 h-5" />
            ) : (
              <AlertTriangle className="w-5 h-5" />
            )}
            <span className="font-semibold">
              {threatCount === 0 ? 'No Threats Detected' : `${threatCount} Issue${threatCount > 1 ? 's' : ''} Found`}
            </span>
          </div>
        </div>
        
        {data.domain && (
          <p className="text-gray-300">
            <span className="font-medium">Domain:</span> {data.domain}
          </p>
        )}
        {data.name && (
          <p className="text-gray-300">
            <span className="font-medium">URL:</span> 
            <a 
              href={data.name} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 ml-2 inline-flex items-center gap-1"
            >
              {data.name}
              <ExternalLink className="w-4 h-4" />
            </a>
          </p>
        )}
      </div>

      {/* Security Details Table */}
      <div className="bg-[#1c1f26] rounded-xl overflow-hidden border border-gray-700">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-800">
              <tr>
                <th className="p-4 text-left text-gray-300 font-semibold">Security Category</th>
                <th className="p-4 text-left text-gray-300 font-semibold">Status</th>
                <th className="p-4 text-left text-gray-300 font-semibold">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {securityItems.map((item, index) => (
                <tr key={index} className="hover:bg-gray-800/50 transition-colors">
                  <td className="p-4">
                    <div className="flex items-center gap-3">
                      {item.icon}
                      <span className="font-medium text-gray-200">{item.category}</span>
                    </div>
                  </td>
                  <td className={`p-4 font-semibold ${item.colorClass}`}>
                    {item.statusText}
                  </td>
                  <td className="p-4 text-gray-300 max-w-md">
                    <div className="break-words">
                      {item.details}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* PDF Report Section */}
      <div className="text-center mt-8 p-6 bg-[#1c1f26] rounded-xl border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Detailed Report</h3>
        {data?.pdf ? (
          <a
            href={data.pdf}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
          >
            <ExternalLink className="w-5 h-5" />
            Download PDF Report
          </a>
        ) : (
          <div className="text-gray-400">
            <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
            <p>PDF report is not available for this scan</p>
          </div>
        )}
      </div>

      {/* Recommendations */}
      {threatCount > 0 && (
        <div className="mt-6 p-6 bg-yellow-900/20 rounded-xl border border-yellow-700/50">
          <h3 className="text-lg font-semibold text-yellow-400 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Security Recommendations
          </h3>
          <ul className="space-y-2 text-gray-300">
            <li>• Review and address all identified security issues immediately</li>
            <li>• Keep all software and CMS platforms updated to the latest versions</li>
            <li>• Implement proper security headers for enhanced protection</li>
            <li>• Regular security scans are recommended to maintain security posture</li>
            <li>• Consider implementing a Web Application Firewall (WAF)</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default ReportDetails;