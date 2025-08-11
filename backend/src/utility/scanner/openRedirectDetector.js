import axios from 'axios';
import { URL } from 'url';

export const detectOpenRedirects = async (baseUrl) => {
  // Common parameter names to test for open redirects
  const redirectParams = ['redirect', 'url', 'next', 'continue', 'dest'];
  const testUrl = 'https://example.com'; // External URL to test redirect
console.log('Scanning for open redirects');
  try {
    for (const param of redirectParams) {
      // Build a URL with the test redirect parameter
      const url = new URL(baseUrl);
      url.searchParams.set(param, testUrl);

      // Make a request but don't follow redirects automatically
      const response = await axios.get(url.toString(), {
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400, // Accept 3xx
      });

      // Check if response is a redirect to the testUrl
      const location = response.headers.location;
      if (location && location.startsWith(testUrl)) {
        return { found: true, param, redirectLocation: location };
      }
    }

    return { found: false };
  } catch (error) {
    // Handle axios errors (like 302 with no redirect following)
    if (error.response && error.response.status >= 300 && error.response.status < 400) {
      const location = error.response.headers.location;
      if (location && location.startsWith('https://example.com')) {
        return { found: true, redirectLocation: location };
      }
    }
    return { error: 'Error detecting open redirects', details: error.message };
  }
};
