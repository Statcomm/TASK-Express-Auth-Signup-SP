const User = require("../../models/Users")
const bcrypt = require ("bcrypt")
const jwt = require("jsonwebtoken")
const { JWT_EXP, JWT_SECRETKEY } = require("../../config/key")

exports.signUp = async (req,res,next) => {
    try { 
    const saltRounds = 10
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds)

    req.body.password=hashedPassword
    const user = await User.create(req.body)
    
    const payload = {username: user.username, id: user.id, exp:Date.now() + JWT_EXP}
    const token = jwt.sign(payload, JWT_SECRETKEY)
    return res.status(201).json({token: token, message:"User Created!"})
    } catch (error) {
        next(error)
    }
}