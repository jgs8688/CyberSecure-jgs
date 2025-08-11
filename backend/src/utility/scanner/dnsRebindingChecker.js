import dns from 'dns/promises';

export const checkDNSRebinding = async (url) => {
  try {
    const hostname = new URL(url).hostname;
    console.log('Checking DNS rebinding for:', hostname);

    const records = await dns.resolve4(hostname);
    const isRebindingRisk = records.some(ip => ip.startsWith('127.') || ip === '0.0.0.0');
    return { found: isRebindingRisk, records };
  } catch (err) {
    return { error: 'Error checking DNS', details: err.message };
  }
};
