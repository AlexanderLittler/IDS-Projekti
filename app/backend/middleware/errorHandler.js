const APIError = require('../errors/apierror')
const BadRequest = require('../errors/badRequest')
const { StatusCodes } = require('http-status-codes')

const errorHandler = (err, _req, res, _next) => {
  // Check if error is Mongoose validation error
  if (err.name === 'ValidationError') {
    let errors = {}
    Object.keys(err.errors).forEach((key) => {
      errors.key = err.errors[key].message
    })
    return res.status(StatusCodes.BAD_REQUEST).send({ success: false, message: err.message})
  }
  // Check if error is Mongoose duplicate id error
  if (err.code === 11000) {
    return res.status(StatusCodes.CONFLICT).send({ success: false, message: 'Duplicate order_id' })
  }
  // Check if error is from APIError class
  if (err instanceof APIError) {
    console.log('Error code: ' + err.statusCode + ', error message: ' + err.message)
    return res.status(err.statusCode).json({ message: err.message})
  }
  // Check if error is from BadRequest class
  if (err instanceof BadRequest) {
    return res.status(err.statusCode).json({ message: err.message})
  }
  // If error is not handled by earlier if statements => 500
  return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err)
}

module.exports = errorHandler