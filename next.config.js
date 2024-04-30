/** @type {import('next').NextConfig} */
const nextConfig = {
    experimental: {
        serverActions: {
            allowedOrigins: ['127.0.0.1:3000']
        }
    }
};

module.exports = nextConfig;
