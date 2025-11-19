const WINDOW_MS = 60_000; // 60 seconds
const lastHit = new Map(); // ip -> timestamp (ms)

module.exports = function rateLimiter(req, res, next) {
  const now = Date.now();
  const ip = req.ip;

  const last = lastHit.get(ip);
  if (last && now - last < WINDOW_MS) {
    const retryAfterSec = Math.ceil((WINDOW_MS - (now - last)) / 1000);
    res.setHeader("Retry-After", retryAfterSec.toString());
    return res.status(429).json({ message: "Too Many Requests" });
  }

  lastHit.set(ip, now);

  next();
};
