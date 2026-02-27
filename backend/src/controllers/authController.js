import bcrypt from 'bcrypt'
import User from '../models/User.js'
import Session from '../models/Session.js'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'

const ACCESS_TOKEN_TTL = '30m'
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000

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

export const signIn = async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({
        message: 'All fields are required'
      })
    }

    const user = await User.findOne({ username })
    if (!user) {
      return res.status(401).json({ message: "Username or password is not correct" })
    }

    // check password
    const passwordCorrect = await bcrypt.compare(password, user.hashPassword)
    if (!passwordCorrect) {
      return res.status(401).json({ message: 'Username or password is not correct' })
    }

    // create access token with JWT
    const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_TTL })

    // create refresh token
    const refreshToken = crypto.randomBytes(64).toString('hex')
    await Session.create({
      userId: user._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    })

    // return refresh token inside cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: REFRESH_TOKEN_TTL,
    })

    return res.status(200).json({ message: `User ${user.displayName} logged in!`, accessToken })
  } catch (error) {
    console.error('SignUp error', error)
    return res.status(500).json({ message: "System error" })
  }
}

export const signOut = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken

    if (token) {
      await Session.deleteOne({ refreshToken: token })
      res.clearCookie("refreshToken")
    }

    return res.sendStatus(204)
  } catch (error) {
    console.error('SignUp error', error)
    return res.status(500).json({ message: "System error" })
  }
}