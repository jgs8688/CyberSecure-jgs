import crypto from 'crypto';

const generateOTP = () => {
  return crypto.randomBytes(3).toString('hex'); 
}
export default generateOTP;
