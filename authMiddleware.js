const jwt = require('jsonwebtoken'); // FIREBASE_REPLACE: Remove later.
const User = require('../models/User');

const protect = async (req, res, next) => {
    let token;

    // Check if the 'token' cookie exists
    if (req.cookies.token) {
        try {
            token = req.cookies.token;

            // 1. Verify the token
            // FIREBASE_REPLACE_START: 
            // With Firebase, you will usually get the token from 'req.headers.authorization' (Bearer token).
            // You will replace jwt.verify() with: 
            // const decodedToken = await admin.auth().verifyIdToken(token);
            const decoded = jwt.verify(token, 'YOUR_SECRET_KEY_HERE_123'); 
            // FIREBASE_REPLACE_END

            // 2. Get user from the database
            // FIREBASE_REPLACE_START:
            // You will likely search by 'firebaseUid' instead of MongoDB '_id'.
            // req.user = await User.findOne({ firebaseUid: decoded.uid }).select('-password');
            req.user = await User.findById(decoded.id).select('-password');
            // FIREBASE_REPLACE_END

            next(); // Success! Move to the controller (e.g., upvoteVideo)
        } catch (error) {
            console.error(error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const admin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next(); // User is admin, proceed!
    } else {
        res.status(403).json({ message: 'Not authorized as an admin' });
    }
};


module.exports = { protect, admin };