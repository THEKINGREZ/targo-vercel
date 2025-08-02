// config.js
const config = {
  ftp: {
    host: process.env.FTP_HOST,
    user: process.env.FTP_USER,
    password: process.env.FTP_PASSWORD
  },
  ftpPublicUrl: process.env.FTP_PUBLIC_URL,
  avatarPublicUrl: process.env.AVATAR_PUBLIC_URL
};
module.exports = config;