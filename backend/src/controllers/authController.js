import bcrypt from 'bcrypt'
import User from '../models/User.js'

export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({
        message: 'All fields are required'
      })
    }

    // check username exist
    const duplicateUsername = await User.findOne({ username })
    if (duplicateUsername) {
      return res.status(409).json({ message: "Username is existed" })
    }

    // hash password
    const hashPassword = await bcrypt.hash(password, 10)

    await User.create({
      username,
      hashPassword,
      email,
      displayName: `${firstName} ${lastName}`
    })

    return res.sendStatus(204)
  } catch (error) {
    console.error('SignUp error', error)
    return res.status(500).json({ message: "System error" })
  }
}