const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Register new user
exports.register = async (req, res) => {
    try {
        const { name, mobileNumber } = req.body;

        // Validate input
        if (!name || !mobileNumber) {
            return res.status(400).json({
                status: 'error',
                message: 'Name and mobile number are required'
            });
        }

        // Check if user already exists
        let user = await User.findOne({ mobileNumber });
        if (user) {
            return res.status(400).json({
                status: 'error',
                message: 'User already exists'
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + parseInt(process.env.OTP_EXPIRY_MINUTES || 10));

        // Create new user
        user = new User({
            name,
            mobileNumber,
            otp: {
                code: otp,
                expiresAt: otpExpiry,
                attempts: 0
            }
        });

        await user.save();

        // In production, integrate with SMS service to send OTP
        res.status(201).json({
            status: 'success',
            message: 'User registered successfully',
            otp: otp // Remove in production
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error registering user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Login with mobile number
exports.login = async (req, res) => {
    try {
        const { mobileNumber } = req.body;

        // Validate input
        if (!mobileNumber) {
            return res.status(400).json({
                status: 'error',
                message: 'Mobile number is required'
            });
        }

        // Check if user exists
        const user = await User.findOne({ mobileNumber });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(401).json({
                status: 'error',
                message: 'Account is deactivated'
            });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + parseInt(process.env.OTP_EXPIRY_MINUTES || 10));

        // Update user's OTP
        user.otp = {
            code: otp,
            expiresAt: otpExpiry,
            attempts: 0
        };
        await user.save();

        // In production, integrate with SMS service to send OTP
        res.json({
            status: 'success',
            message: 'OTP sent successfully',
            otp: otp // Remove in production
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
    try {
        const { mobileNumber, otp } = req.body;

        // Validate input
        if (!mobileNumber || !otp) {
            return res.status(400).json({
                status: 'error',
                message: 'Mobile number and OTP are required'
            });
        }

        // Find user
        const user = await User.findOne({ mobileNumber });
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Check if OTP exists and is valid
        if (!user.isOTPValid()) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired OTP'
            });
        }

        // Verify OTP
        if (user.otp.code !== otp) {
            await user.incrementOTPAttempts();
            return res.status(400).json({
                status: 'error',
                message: 'Invalid OTP'
            });
        }

        // Update last login
        user.lastLogin = new Date();
        user.otp = undefined;
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.json({
            status: 'success',
            message: 'OTP verified successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                mobileNumber: user.mobileNumber,
                role: user.role
            }
        });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error verifying OTP',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};
