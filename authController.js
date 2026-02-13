const User = require('../models/User'); // first need to create a user model if not create yet
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Helper to set Cookie & Send Response
const sendTokenResponse = (user, statusCode, res) => {
    // Create token
    const token = jwt.sign({ id: user._id }, 'YOUR_SECRET_KEY_HERE_123', {
        expiresIn: '30d'
    });

    // Cookie options
    const options = {
        // Uncomment below line if you need to keep the 30 days expiry
        // expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        httpOnly: true, // Security: Client-side JS cannot access this cookie (prevents XSS)
        secure: false,
        sameSite: 'lax'
    };



        res.status(statusCode)
        .cookie('token', token, options) 
        .json({
            sucess: true
        });
    
};

// Register a new user
const registerUser = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await User.create({
            username,
            email,
            password: hashedPassword,
        });

        // send cookie
        sendTokenResponse(user, 201, res);

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Login user
const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (user && (await bcrypt.compare(password, user.password))) {
            // Use the helper to send cookie
            sendTokenResponse(user, 200, res);
        } else {
            res.status(401).json({ message: "Invalid credentials" });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Logout user (Clear cookie)
// GET /api/auth/logout
const logoutUser = async (req, res) => {
    // FIREBASE_REPLACE: Firebase logout is handled on the frontend (firebase.auth().signOut())
    res.cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    });
    res.status(200).json({ success: true, data: {} });
};

// @desc    Update user profile
// @route   PUT /api/auth/profile
const updateUserProfile = async (req, res) => {
    try {
        // req.user is already set by our 'protect' middleware
        const user = await User.findById(req.user._id);

        if (user) {
            // Update fields if they are provided in the body, otherwise keep old ones
            user.username = req.body.username || user.username;
            user.email = req.body.email || user.email;
            

            // If user sends a password, we can hash and update it (Optional)
            // if (req.body.password) {
            //     const salt = await bcrypt.genSalt(10);
            //     user.password = await bcrypt.hash(req.body.password, salt);
            // }

            const updatedUser = await user.save();

            // Send back the fresh data so React can update immediately
            res.json({
                _id: updatedUser._id,
                username: updatedUser.username,
                email: updatedUser.email,
                
            });
        } else {
            res.status(404).json({ message: "User not found" });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


module.exports = { registerUser, loginUser, logoutUser, updateUserProfile };
