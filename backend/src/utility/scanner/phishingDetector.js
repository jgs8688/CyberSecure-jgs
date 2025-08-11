export const detectPhishingPages = async (url) => {
  try {
    const { data } = await axios.get(url);
console.log('Scanning for phishing pages');
    // Keywords to check
    const phishingKeywords = /login|password|credit|verify|account|security|confirm/i;
    const foundKeywords = phishingKeywords.test(data);

    // Simple form action check for suspicious external POST URLs
    const formActionSuspicious = /<form[^>]+action=["']?(http:\/\/|https:\/\/)(?!yourdomain\.com)/i.test(data);

    return { 
      found: foundKeywords || formActionSuspicious,
      details: {
        foundKeywords,
        formActionSuspicious
      }
    };
  } catch (err) {
    return { error: 'Error scanning for phishing pages', details: err.message };
  }
};
