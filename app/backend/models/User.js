const mongoose = require('mongoose')
const { Schema } = mongoose

const userSchema = new Schema({
  username: {
    type: String,
    required: [true, 'You must provide a username'],
  },
  email: {
    type: String,
    required: [true, 'You must provide your email'],
  },
  passwordHash: String,
})

module.exports = mongoose.model('User', userSchema, 'users')