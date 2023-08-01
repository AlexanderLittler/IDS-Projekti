const express = require('express')
const router = express.Router()

const {  
  createUser,
  getSingleUser,
  getUsers
} = require('../controllers/userControllers')

router.post('/register', createUser)
router.get('/users/:id', getSingleUser)
router.get('/users/', getUsers)

module.exports = router