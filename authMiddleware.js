const jwt = require('jsonwebtoken'); 
const User = require('../models/User'); // first create user model if not created yet

const protect = async (req, res, next) => {
    let token;

    // Check if the 'token' cookie exists
    if (req.cookies.token) {
        try {
            token = req.cookies.token;
            
            const decoded = jwt.verify(token, 'YOUR_SECRET_KEY_HERE_123'); 
            
            req.user = await User.findById(decoded.id).select('-password');
           

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

// (Optional)
// const admin = (req, res, next) => {
//     if (req.user && req.user.role === 'admin') {
//         next(); // User is admin, proceed!
//     } else {
//         res.status(403).json({ message: 'Not authorized as an admin' });
//     }
// };

module.exports = { protect };
// module.exports = { protect, admin };
