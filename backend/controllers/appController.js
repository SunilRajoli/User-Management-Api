import UserModel from '../model/User.model.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import ENV from '../config.js';
import otpGenerator from 'otp-generator';


/** middleware for verify user */
export async function verifyUser(req, res, next){
    try {
        
        const { username } = req.method == "GET" ? req.query : req.body;

        // check the user existance
        let exist = await UserModel.findOne({ username });
        if(!exist) return res.status(404).send({ error : "Can't find User!"});
        next();

    } catch (error) {
        return res.status(404).send({ error: "Authentication Error"});
    }
}


/** POST: http://localhost:8080/api/register 
 * @param : {
  "username" : "example123",
  "password" : "admin123",
  "email": "example@gmail.com",
  "firstName" : "bill",
  "lastName": "william",
  "mobile": 8009860560,
  "address" : "Apt. 556, Kulas Light, Gwenborough",
  "profile": ""
}
*/
export function register(req, res) {
    const { username, password, profile, email } = req.body;

    // Check if username already exists
    const existUsernamePromise = UserModel.findOne({ username })
        .then((user) => {
            if (user) {
                throw { error: "Username already in use. Please choose a different username." };
            }
        });

    // Check if email already exists
    const existEmailPromise = UserModel.findOne({ email })
        .then((user) => {
            if (user) {
                throw { error: "Email already registered. Please use a different email address." };
            }
        });

    // Execute promises to check existing username and email
    Promise.all([existUsernamePromise, existEmailPromise])
        .then(() => {
            // Hash the password
            return bcrypt.hash(password, 10);
        })
        .then((hashedPassword) => {
            // Create new user instance
            const newUser = new UserModel({
                username,
                password: hashedPassword,
                profile: profile || '',
                email
            });

            // Save the new user
            return newUser.save();
        })
        .then(() => {
            // Return success message
            return res.status(201).json({ msg: "User registered successfully." });
        })
        .catch((error) => {
            console.error("Error registering user:", error);
            // Check the type of error and send appropriate response
            if (error && error.error) {
                // Validation error (username or email already exists)
                return res.status(400).json({ error: error.error });
            } else {
                // Internal server error (unexpected error)
                return res.status(500).json({ error: "Internal Server Error" });
            }
        });
}


/** POST: http://localhost:8080/api/login 
 * @param: {
  "username" : "example123",
  "password" : "admin123"
}
*/
export async function login(req,res){
   
    const { username, password } = req.body;

    try {
        
        UserModel.findOne({ username })
            .then(user => {
                bcrypt.compare(password, user.password)
                    .then(passwordCheck => {

                        if(!passwordCheck) return res.status(400).send({ error: "Don't have Password"});

                        // create jwt token
                        const token = jwt.sign({
                                        userId: user._id,
                                        username : user.username
                                    }, ENV.JWT_SECRET , { expiresIn : "24h"});

                        return res.status(200).send({
                            msg: "Login Successful...!",
                            username: user.username,
                            token
                        });                                    

                    })
                    .catch(error =>{
                        return res.status(400).send({ error: "Password does not Match"})
                    })
            })
            .catch( error => {
                return res.status(404).send({ error : "Username not Found"});
            })

    } catch (error) {
        return res.status(500).send({ error});
    }
}

//GET: http://localhost:8080/api/user/example123  
export async function getUser(req, res) {
    const { username } = req.params;

    try {
        if (!username) {
            return res.status(400).json({ error: "Invalid Username" });
        }

        const user = await UserModel.findOne({ username });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Remove sensitive data (e.g., password) from the user object
        const { password, ...userData } = user.toObject();

        return res.status(200).json(userData);
    } catch (error) {
        console.error("Error retrieving user:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
}

/** PUT: http://localhost:8080/api/updateuser 
 * @param: {
  "header" : "<token>"
}
body: {
    firstName: '',
    address : '',
    profile : ''
}
*/
export async function updateUser(req, res) {
    try {
        const id = req.query.id;
        //const { userId } = req.user;

        if (id) {
            return res.status(400).json({ error: "User ID not provided" });
        }

        const body = req.body;

        // Update the user record
        const updatedUser = await UserModel.findByIdAndUpdate(id, body, { new: true });

        if (updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({ msg: "Record Updated", user: updatedUser });
    } catch (error) {
        console.error("Error updating user:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
}


/** GET: http://localhost:8080/api/generateOTP */
export async function generateOTP(req,res){
    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    res.status(201).send({ code: req.app.locals.OTP })
}


/** GET: http://localhost:8080/api/verifyOTP */
export async function verifyOTP(req,res){
    const { code } = req.query;
    if(parseInt(req.app.locals.OTP) === parseInt(code)){
        req.app.locals.OTP = null; // reset the OTP value
        req.app.locals.resetSession = true; // start session for reset password
        return res.status(201).send({ msg: 'Verify Successsfully!'})
    }
    return res.status(400).send({ error: "Invalid OTP"});
}


// successfully redirect user when OTP is valid
/** GET: http://localhost:8080/api/createResetSession */
export async function createResetSession(req, res) {
    try {
        if (req.app.locals.resetSession) {
            console.log("Reset Session Status:", req.app.locals.resetSession);
            return res.status(201).send({ flag: req.app.locals.resetSession });
        } else {
            console.log("Reset Session Expired");
            return res.status(440).send({ error: "Session expired!" });
        }
    } catch (error) {
        console.error("Error creating reset session:", error);
        return res.status(500).send({ error: "Internal Server Error" });
    }
}

// update the password when we have valid session
/** PUT: http://localhost:8080/api/resetPassword */
export async function resetPassword(req, res) {
    try {
        // Check if resetSession is active
        if (!req.app.locals.resetSession) {
            return res.status(440).send({ error: "Session expired!" });
        }

        const { username, password } = req.body;

        // Find user by username
        const user = await UserModel.findOne({ username });
        if (!user) {
            return res.status(404).send({ error: "Username not found" });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user's password
        await UserModel.updateOne({ username: user.username }, { password: hashedPassword });

        // Reset session after password update
        req.app.locals.resetSession = false;

        return res.status(201).send({ msg: "Password updated successfully" });
    } catch (error) {
        console.error("Error resetting password:", error);
        return res.status(500).send({ error: "Internal Server Error" });
    }
}