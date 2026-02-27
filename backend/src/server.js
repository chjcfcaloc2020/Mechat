import express from 'express'
import dotenv from 'dotenv'
import authRoute from './routes/authRoute.js'
import cookieParser from 'cookie-parser'
import { connectDB } from './libs/db.js'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// middlewares
app.use(express.json())
app.use(cookieParser())

// public routes
app.use('/api/auth', authRoute)

// private routes

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
  })
})