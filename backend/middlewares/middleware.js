import jwt from 'jsonwebtoken';
import Admin from '../models/admin.models.js'; 
import User from '../models/user.models.js'; 
import dotenv from "dotenv";
dotenv.config();
// JWT secret key - should be in environment variables
const JWT_SECRET = process.env.JWT_SECRET;

// Base authentication function
const authenticateToken = async (req, res, next, Model, userType) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists in database
    const user = await Model.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: `${userType} not found`
      });
    }

    // Attach user to request object
    req.user = user;
    req.userType = userType;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        success: false,
        message: 'Invalid token'
      });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(403).json({
        success: false,
        message: 'Token expired'
      });
    } else {
      return res.status(500).json({
        success: false,
        message: 'Server error during authentication'
      });
    }
  }
};

// Admin middleware
export const authenticateAdmin = async (req, res, next) => {
  await authenticateToken(req, res, next, Admin, 'Admin');
};

// User middleware
export const authenticateUser = async (req, res, next) => {
  await authenticateToken(req, res, next, User, 'User');
};

// Combined middleware - accepts both admin and user
export const authenticateAdminOrUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Try to find user in Admin collection first
    let user = await Admin.findById(decoded.id).select('-password');
    let userType = 'Admin';
    
    // If not found in Admin, try User collection
    if (!user) {
      user = await User.findById(decoded.id).select('-password');
      userType = 'User';
    }
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    req.user = user;
    req.userType = userType;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        success: false,
        message: 'Invalid token'
      });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(403).json({
        success: false,
        message: 'Token expired'
      });
    } else {
      return res.status(500).json({
        success: false,
        message: 'Server error during authentication'
      });
    }
  }
};


// Utility function to generate JWT tokens
export const generateToken = (userId, expiresIn = '24h') => {
  return jwt.sign(
    { id: userId },
    JWT_SECRET,
    { expiresIn }
  );
};

// Utility function to verify tokens (useful for testing)
export const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};
