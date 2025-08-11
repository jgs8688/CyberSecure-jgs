import axios from 'axios';
import * as  cheerio from 'cheerio';

export const detectHiddenScripts = async (url) => {
  try {
    const { data } = await axios.get(url);
    const $ = cheerio.load(data);
    const hiddenScripts = [];
    // Check for inline scripts that may contain eval or document.write
    console.log('Scanning for hidden scripts');

   $('script').each((_, el) => {
  const styleAttr = $(el).attr('style');
  const isHidden = styleAttr && /display\s*:\s*none/.test(styleAttr);

  const content = $(el).html();
  const hasSuspiciousCode = content && /eval|document\.write|setTimeout|setInterval/.test(content);

  if (isHidden || hasSuspiciousCode) {
    hiddenScripts.push({
      preview: content?.slice(0, 100) || '',
      hidden: !!isHidden,
    });
  }
});


    return { found: hiddenScripts.length > 0, samples: hiddenScripts };
  } catch (err) {
    return { error: 'Error detecting hidden scripts', details: err.message };
  }
};
