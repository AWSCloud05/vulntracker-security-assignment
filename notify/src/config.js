const SERVICE_KEY = process.env.NOTIFY_SERVICE_KEY || '';

if (Buffer.byteLength(SERVICE_KEY) < 32) {
  throw new Error('NOTIFY_SERVICE_KEY must contain at least 32 characters');
}

module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',
  SERVICE_KEY,
  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
