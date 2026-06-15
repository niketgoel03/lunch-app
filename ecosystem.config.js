// PM2 process configuration.
// Start with:  pm2 start ecosystem.config.js   (run as the dedicated app user)
//
// Single instance / fork mode is intentional: the app keeps an in-memory
// settings cache and rate-limit counters, which must not be duplicated across
// cluster workers. Scale horizontally only after moving that state to a shared
// store (e.g. Redis).
module.exports = {
  apps: [
    {
      name: 'lunch-app',
      script: 'server.js',
      cwd: '/opt/lunch-app',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: '300M',
      env: {
        NODE_ENV: 'production',
        // App config is read from /opt/lunch-app/.env via dotenv.
      },
    },
  ],
};
