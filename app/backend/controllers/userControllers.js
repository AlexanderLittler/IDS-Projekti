const APIError = require('../errors/apierror')
const BadRequest = require('../errors/badRequest')
const NotFound = require('../errors/notFound')
const { StatusCodes } = require('http-status-codes')
const User = require('../models/User')
const bcrypt = require('bcryptjs')

const createUser = async (req, res) => {
  const { username, email, password, passwordCheck } = req.body

  // Check if request contains all the necessary information.
  if (!username) {
    throw new BadRequest('username is required')
  }
  if (!email) {
    throw new BadRequest('email is required')
  }  
  if (!password) {
    throw new BadRequest('password is required')
  }
  if (!passwordCheck) {
    throw new BadRequest('passwordCheck is required')
  }
  
  // Check if usernname is already in use.
  const userExists = await User.findOne({username})
  // If username is already in use => throw error
  if (userExists) {
    throw new APIError(`User already exists: ${username}`, StatusCodes.CONFLICT)    
  }
 
  // Check if email is already in use.
  const emailExist = await User.findOne({ email })
  // If email is already in use => throw error
  if (emailExist) {
    throw new APIError(`Email already exists ${email}`, StatusCodes.CONFLICT)
  }

  // Use bcrypt to hash password  
  if (password === passwordCheck) {
    const saltRounds = 10
    const passwordHash = await bcrypt.hash(password, saltRounds)
    const user = new User({
      username,
      email,
      passwordHash
    })

    await user.save()
    res.status(StatusCodes.CREATED).json({user})
  } else {
    throw new BadRequest("Password and passwordCheck don't match")
  }
}

const getSingleUser = async (req, res) => {
  const { id } = req.params
  const user = await User.findById(id)
  if (!user) {
    throw new NotFound(`No user found with id ${id}`)
  }
  res.status(StatusCodes.OK).json({user})
}

const getUsers = async (req, res) => {
  const users = await User.find({})
  res.status(StatusCodes.OK).json(users)
}

module.exports = {
  createUser,
  getSingleUser,
  getUsers
}
