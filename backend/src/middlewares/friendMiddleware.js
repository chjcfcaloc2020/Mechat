import Conversation from "../models/Conversation.js";
import Friend from '../models/Friend.js'

const pair = (a, b) => (a < b ? [a, b] : [b, a])

export const checkFriendship = async (req, res, next) => {
  try {
    const me = req.user._id.toString()
    const recipientId = req.body?.recipientId ?? null
    const memberIds = req.body?.memberIds ?? []

    if (!recipientId && memberIds.length === 0) {
      return res.status(400).json({ message: "Need provide recipientId or memberIds" })
    }

    if (recipientId) {
      const [userA, userB] = pair(me, recipientId)
      const isFriend = await Friend.findOne({ userA, userB })

      if (!isFriend) {
        return res.status(403).json({ message: "You have not friendship with user" })
      }
      return next()
    }

    const friendChecks = memberIds.map(async (memberId) => {
      const [userA, userB] = pair(me, memberId)
      const friend = await Friend.findOne({ userA, userB })
      return friend ? null : memberId
    })
    const results = await Promise.all(friendChecks)
    const notFriend = results.filter(Boolean)

    if (notFriend.length > 0) {
      return res.status(403).json({ message: "You just can add your friend into gourp", notFriend })
    }
  } catch (error) {
    console.error("Error! When check friendship", error)
    return res.status(500).json({ message: "System error" })
  }
}

export const checkGroupMembership = async (req, res, next) => {
  try {
    const {conversationId} = req.body
    const userId = req.user._id
    const conversation = await Conversation.findById(conversationId)

    if (!conversation) {
      return res.status(404).json({ message: "Not found group" })
    }

    const isMember = conversation.participants.some(
      (p) => p.userId.toString() === userId.toString()
    )

    if (!isMember) {
      return res.status(403).json({ message: "You are not in this group" })
    }

    req.conversation = conversation

    next()
  } catch (error) {
    console.error("Error! When check membership", error)
    return res.status(500).json({ message: "System error" })
  }
}