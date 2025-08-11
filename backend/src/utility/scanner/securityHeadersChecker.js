import axios from 'axios';

export const checkSecurityHeaders = async (url) => {
  try {
    const response = await axios.get(url);
    const headers = response.headers;
    // Check for common security headers
    console.log('Checking security headers');

const requiredHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy'
    ];    const missing = requiredHeaders.filter(h => !headers[h]);
    return { found: missing.length > 0, missing };
  } catch (err) {
    return { error: 'Error checking headers', details: err.message };
  }
};




