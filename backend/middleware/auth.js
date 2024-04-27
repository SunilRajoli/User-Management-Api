
import jwt from 'jsonwebtoken';
import ENV from '../config.js';

/** auth middleware */
export default async function Auth(req, res, next){
    try {
        // Access the Authorization header to validate the request
        const token = req.headers.authorization.split(" ")[1];

        // Retrieve the user details for the logged-in user
        const decodedToken = await jwt.verify(token, ENV.JWT_SECRET);

        req.user = decodedToken;

        next();
    } catch (error) {
        console.error("Authentication Error:", error);
        res.status(401).json({ error: "Authentication Failed!" });
    }
}

export function localVariables(req, res, next){
    req.app.locals = {
        OTP : null,
        resetSession : false
    };
    next();
}
