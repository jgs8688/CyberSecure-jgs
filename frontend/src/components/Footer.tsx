import React from 'react';

const socialLinks = [
  {
    href: 'https://twitter.com/yourprofile',
    label: 'Twitter',
    icon: (
      <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
        <path d="M23.954 4.569c-.885.389-1.83.654-2.825.775a4.92 4.92 0 002.163-2.724 9.83 9.83 0 01-3.127 1.195 4.916 4.916 0 00-8.374 4.482A13.94 13.94 0 011.671 3.149a4.916 4.916 0 001.523 6.573 4.903 4.903 0 01-2.229-.616c-.054 2.28 1.581 4.415 3.949 4.89a4.902 4.902 0 01-2.224.084 4.917 4.917 0 004.59 3.417 9.867 9.867 0 01-6.102 2.105c-.395 0-.788-.023-1.174-.068a13.945 13.945 0 007.557 2.212c9.054 0 14.002-7.496 14.002-13.986 0-.21-.005-.423-.015-.633A10.012 10.012 0 0024 4.59z" />
      </svg>
    ),
  },
  {
    href: 'https://linkedin.com/in/yourprofile',
    label: 'LinkedIn',
    icon: (
      <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
        <path d="M4.98 3.5c0 1.381-1.11 2.5-2.48 2.5C1.11 6 0 4.881 0 3.5 0 2.12 1.11 1 2.5 1c1.37 0 2.48 1.12 2.48 2.5zM.43 8h4.94v13H.43V8zm7.56 0h4.735v1.771h.068c.66-1.253 2.274-2.574 4.685-2.574 5.01 0 5.93 3.3 5.93 7.59V21H18.37v-6.15c0-1.47-.03-3.36-2.05-3.36-2.05 0-2.36 1.6-2.36 3.25V21H8.01V8z" />
      </svg>
    ),
  },
  {
    href: 'https://github.com/yourprofile',
    label: 'GitHub',
    icon: (
      <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
        <path d="M12 .5C5.648.5.5 5.648.5 12c0 5.095 3.292 9.406 7.86 10.944.574.104.784-.25.784-.554 0-.273-.01-.997-.016-1.957-3.2.696-3.878-1.543-3.878-1.543-.523-1.33-1.276-1.685-1.276-1.685-1.044-.713.08-.699.08-.699 1.155.081 1.763 1.186 1.763 1.186 1.027 1.76 2.696 1.252 3.35.957.105-.744.402-1.252.731-1.54-2.553-.293-5.238-1.276-5.238-5.68 0-1.254.446-2.28 1.177-3.084-.12-.294-.51-1.477.11-3.08 0 0 .96-.31 3.14 1.177a10.99 10.99 0 015.72 0c2.18-1.487 3.14-1.177 3.14-1.177.62 1.603.23 2.786.11 3.08.73.804 1.177 1.83 1.177 3.084 0 4.416-2.69 5.385-5.26 5.673.41.355.78 1.056.78 2.13 0 1.538-.015 2.78-.015 3.16 0 .306.21.663.79.55C20.7 21.406 24 17.095 24 12c0-6.352-5.148-11.5-11.5-11.5z" />
      </svg>
    ),
  },
];

const Footer: React.FC = () => {
  return (
    <footer className="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 text-gray-300 backdrop-blur border-t border-gray-700 w-full py-10 mt-10">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-8">
        <p className="text-sm text-center md:text-left">&copy; {new Date().getFullYear()} <span className="text-white font-semibold">CyberSecure-web</span>. All rights reserved.</p>

        <nav className="flex flex-wrap justify-center gap-6 text-sm">
          <a href="#home" className="hover:text-cyan-400 transition duration-300">Home</a>
          <a href="#features" className="hover:text-cyan-400 transition duration-300">Features</a>
          <a href="#about" className="hover:text-cyan-400 transition duration-300">About</a>
          <a href="#contact" className="hover:text-cyan-400 transition duration-300">Contact</a>
        </nav>

        <div className="flex gap-6">
          {socialLinks.map(({ href, label, icon }) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={label}
              title={label}
              className="hover:text-cyan-400 transform hover:scale-110 transition duration-300"
            >
              {icon}
            </a>
          ))}
        </div>
      </div>
    </footer>
  );
};

export default Footer;
