import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const secretKey = process.env.SECRET_KEY;

const handleError = (err, req, res, next) => {
  const statusCode =
    err.status || (err.code && err.code.startsWith("SQLITE_") ? 500 : 400);
  res.status(statusCode).json({ message: err.message });
};

const logger = (req, res, next) => {
  console.log(`${req.method} ${req.originalUrl}`);
  next();
};

const authenticate = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Failed to authenticate token" });
    req.user = decoded;
    next();
  });
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
};

export { handleError, logger, authenticate, authorize };
