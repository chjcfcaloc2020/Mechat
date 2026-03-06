import express from 'express'
import { 
  createConversation, 
  getConversations, 
  getMessages 
} from '../controllers/conversationController.js'
import { checkFriendship } from '../middlewares/friendMiddleware.js'

const router = express.Router()

router.get("/:conversationId/messages", getMessages)
router.get("/", getConversations)
router.post("/", checkFriendship, createConversation)

export default router