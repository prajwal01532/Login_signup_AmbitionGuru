const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        // Get token from header
        const authHeader = req.header('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                status: 'error',
                message: 'No authentication token provided'
            });
        }

        const token = authHeader.replace('Bearer ', '');

        try {
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Check if user still exists
            const user = await User.findById(decoded.userId);
            if (!user) {
                throw new Error();
            }

            // Check if user is active
            if (!user.isActive) {
                return res.status(401).json({
                    status: 'error',
                    message: 'Account is deactivated'
                });
            }

            // Add user to request object
            req.user = user;
            req.token = token;
            next();
        } catch (err) {
            res.status(401).json({
                status: 'error',
                message: 'Invalid authentication token'
            });
        }
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: 'Authentication error'
        });
    }
};

// Middleware for role-based access control
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                status: 'error',
                message: 'You do not have permission to perform this action'
            });
        }
        next();
    };
};

module.exports = { auth, authorize };
