import jwt from 'jsonwebtoken'
import User from '../models/User.js'

export const protectedRoute = async (req, res, next) => {
  try {
    // get token from Header
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
      return res.status(401).json({ message: "Not found access token" })
    }

    // verify token valid
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (err, decodedUser) => {
      if (err) {
        console.error(err)
        return res.status(403).json({ message: "Access token expiration or incorrect!" })
      }
      // find user
      const user = await User.findById(decodedUser.userId).select('-hashPassword')
      if (!user) {
        return res.status(404).json({ message: "User is not exist" })
      }

      req.user = user
      next()
    })
  } catch (error) {
    console.error("Error! When JWT verification inside authMiddleware", error)
    return res.status(500).json({ message: "System error" })
  }
}