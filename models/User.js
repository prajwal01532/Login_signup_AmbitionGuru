const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters long'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    mobileNumber: {
        type: String,
        required: [true, 'Mobile number is required'],
        unique: true,
        trim: true,
        match: [/^[0-9]{10}$/, 'Please enter a valid 10-digit mobile number']
    },
    otp: {
        code: String,
        expiresAt: Date,
        attempts: {
            type: Number,
            default: 0
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    role: {
        type: String,
        enum: ['student', 'teacher', 'admin'],
        default: 'student'
    }
}, {
    timestamps: true
});

// Index for faster queries
userSchema.index({ mobileNumber: 1 });

// Method to check if OTP is valid
userSchema.methods.isOTPValid = function() {
    return this.otp && 
           this.otp.code && 
           this.otp.expiresAt && 
           this.otp.expiresAt > new Date() &&
           this.otp.attempts < 3;
};

// Method to increment OTP attempts
userSchema.methods.incrementOTPAttempts = function() {
    if (this.otp) {
        this.otp.attempts += 1;
    }
    return this.save();
};

module.exports = mongoose.model('User', userSchema);
