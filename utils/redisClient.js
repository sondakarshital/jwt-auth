const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});

client.on('error', (err) => console.error('Redis Error:', err));

client.connect(); // Enable modern Promise-based API

module.exports = client;
