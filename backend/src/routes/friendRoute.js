import express from 'express'

import {
  sendFriendRequest,
  acceptFriendRequest,
  declineFriendRequest,
  getAllFriends,
  getFriendRequests
} from '../controllers/friendController.js'

const router = express.Router()

router.post('/requests', sendFriendRequest)
router.post('/requests/:requestId/accept', acceptFriendRequest)
router.post('/requests/:requestId/decline', declineFriendRequest)

router.get('/requests', getFriendRequests)
router.get('/', getAllFriends)

export default router