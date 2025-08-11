import axios from 'axios';
import * as cheerio from 'cheerio'; 

export const detectCMSVulnerabilities = async (url) => {
  try {
    const response = await axios.get(url);
    const $ = cheerio.load(response.data);
    const metaGenerator = $('meta[name="generator"]').attr('content');

    if (!metaGenerator) {
      return { cms: null, vulnerable: false, info: 'CMS not detected' };
    }

    const cms = metaGenerator.toLowerCase();

    let vulnerable = false;
    let reason = '';
    consolest.log('CMS detected scanning', cms);

    if (cms.includes('wordpress')) {
      vulnerable = true;
      reason = 'WordPress is known for plugin vulnerabilities if not updated.';
    } else if (cms.includes('joomla')) {
      vulnerable = true;
      reason = 'Joomla has had vulnerabilities related to extensions and permissions.';
    } else if (cms.includes('drupal')) {
      vulnerable = true;
      reason = 'Drupal had several critical bugs (e.g., Drupalgeddon).';
    }

    return { cms: metaGenerator, vulnerable, reason };
  } catch (error) {
    return { error: 'Error detecting CMS', details: error.message };
  }
};
