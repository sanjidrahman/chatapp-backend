const jwt = require('jsonwebtoken');
const User = require('./userModel'); // Importing the user model

// Authorization middleware for user routes
const auth = async (req, res, next) => {
    try {
        const authHeaders = req.headers.authorization; // Extracting authorization headers from request
        if (!authHeaders || !authHeaders.split(' ')[1]) { // Checking if authorization headers are present and contain a token
            return res.status(401).json({ message: 'Not Authorized' });
        }

        const token = authHeaders.split(' ')[1];
        const decoded = jwt.verify(token, 'jwt_secret'); // Verifying the token using user secret
        const userData = await User.findOne({ _id: decoded.payload.id }); // Finding admin data based on decoded token

        if (!userData) {
            return res.status(401).json({ message: 'User not found' });
        }

        if (userData.isBlocked) {
            return res.status(403).json({ message: 'Access Denied' });
        }

        // req.body.userId = userData._id;
        req.session.userId = userData._id; // Adding user ID to session for further processing
        next();
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
}

module.exports = auth