import Friend from '../models/Friend.js'
import FriendRequest from '../models/FriendRequest.js'
import User from '../models/User.js'

export const sendFriendRequest = async (req, res) => {
  try {
    const { to, message } = req.body
    const from = req.user._id

    if (from.toString() === to.toString()) {
      return res.status(400).json({ message: "Can not send request to myseft" })
    }

    const userExists = await User.exists({ _id: to })

    if (!userExists) {
      return res.status(404).json({ message: "User not exists" })
    }

    let userA = from.toString()
    let userB = to.toString()

    if (userA > userB) {
      [userA, userB] = [userB, userA]
    }

    const [alreadyFriends, existingRequest] = await Promise.all([
      Friend.findOne({ userA, userB }),
      FriendRequest.findOne({
        $or: [
          { from, to },
          { from: to, to: from }
        ]
      })
    ])

    if (alreadyFriends) {
      return res.status(400).json({ message: "They have been friends" })
    }

    if (existingRequest) {
      return res.status(400).json({ message: "Friend request had been waiting" })
    }

    const request = await FriendRequest.create({ from, to, message })

    return res.status(201).json({ message: "Send friend request success", request })
  } catch (error) {
    console.error("Error sending friend request", error)
    return res.status(500).json({ message: "System error " })
  }
}

export const acceptFriendRequest = async (req, res) => {
  try {
    const { requestId } = req.params
    const userId = req.user._id

    const friendRequest = await FriendRequest.findById(requestId)

    if (!friendRequest) {
      return res.status(404).json({ message: "Not found friend request" })
    }

    if (friendRequest.to.toString() !== userId.toString()) {
      return res.status(403).json({ message: "You have not permission" })
    }

    await Friend.create({
      userA: friendRequest.from,
      userB: friendRequest.to
    })

    await FriendRequest.findByIdAndDelete(requestId)
    const from = await User.findById(friendRequest.from).select("_id displayName avatarUrl").lean()

    return res.status(200).json({
      message: "Accept friend request success",
      newFriend: {
        _id: from?._id,
        displayName: from?.displayName,
        avatarUrl: from?.avatarUrl
      }
    })
  } catch (error) {
    console.error("Error accepting friend request", error)
    return res.status(500).json({ message: "System error" })
  }
}

export const declineFriendRequest = async (req, res) => {
  try {
    const { requestId } = req.params
    const userId = req.user._id

    const friendRequest = await FriendRequest.findById(requestId)

    if (!friendRequest) {
      return res.status(404).json({ message: "Not found friend request" })
    }

    if (friendRequest.to.toString() !== userId.toString()) {
      return res.status(403).json({ message: "You have not permission" })
    }

    await FriendRequest.findByIdAndDelete(requestId)

    return res.sendStatus(204)
  } catch (error) {
    console.error("Error declining friend request", error)
    return res.status(500).json({ message: "System error " })
  }
}

export const getAllFriends = async (req, res) => {
  try {
    const userId = req.user._id
    const friendships = await Friend.find({
      $or: [
        { userA: userId },
        { userB: userId }
      ]
    }).populate("userA", "_id displayName avatarUrl").populate("userB", "_id displayName avatarUrl").lean()

    if (!friendships.length) {
      return res.status(200).json({ friends: [] })
    }

    const friends = friendships.map((f) =>
      f.userA._id.toString() === userId.toString() ? f.userB : f.userA
    )

    return res.status(200).json({ friends })
  } catch (error) {
    console.error("Error getting list friend", error)
    return res.status(500).json({ message: "System error " })
  }
}

export const getFriendRequests = async (req, res) => {
  try {
    const userId = req.user._id
    const popupateFields = "_id username displayName avatarUrl"
    const [sent, received] = await Promise.all([
      FriendRequest.find({ from: userId }).populate("to", popupateFields),
      FriendRequest.find({ to: userId }).populate("from", popupateFields)
    ])

    return res.status(200).json({ sent, received })
  } catch (error) {
    console.error("Error getting friend request", error)
    return res.status(500).json({ message: "System error " })
  }
}