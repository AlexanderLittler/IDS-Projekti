const { StatusCodes } = require('http-status-codes')
const APIError = require('./apierror')

class BadRequest extends APIError {
  constructor(message) {
    super(message)
    this.statusCode = StatusCodes.BAD_REQUEST
  }
}

module.exports = BadRequest