const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Register new user
router.post('/register', async (req, res) => {
    try {
        const { name, mobileNumber } = req.body;

        // Check if user already exists
        let user = await User.findOne({ mobileNumber });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP valid for 10 minutes

        // Create new user
        user = new User({
            name,
            mobileNumber,
            otp: {
                code: otp,
                expiresAt: otpExpiry
            }
        });

        await user.save();

        // In a real application, send OTP via SMS
        // For demo, we'll just send it in response
        res.status(201).json({ 
            message: 'User registered successfully',
            otp: otp // In production, remove this
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login with mobile number
router.post('/login', async (req, res) => {
    try {
        const { mobileNumber } = req.body;

        // Check if user exists
        const user = await User.findOne({ mobileNumber });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);

        // Update user's OTP
        user.otp = {
            code: otp,
            expiresAt: otpExpiry
        };
        await user.save();

        // In production, send OTP via SMS
        res.json({ 
            message: 'OTP sent successfully',
            otp: otp // Remove in production
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
    try {
        const { mobileNumber, otp } = req.body;

        // Find user
        const user = await User.findOne({ mobileNumber });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if OTP is valid and not expired
        if (!user.otp || user.otp.code !== otp || user.otp.expiresAt < new Date()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        // Clear OTP after successful verification
        user.otp = undefined;
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            'your-secret-key', // In production, use environment variable
            { expiresIn: '24h' }
        );

        res.json({
            message: 'OTP verified successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                mobileNumber: user.mobileNumber
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
