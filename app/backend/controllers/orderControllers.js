const Order = require('../models/Order')
const APIError = require('../errors/apierror')
const { StatusCodes } = require('http-status-codes')
const sendEmail = require('../middleware/sendEmail')
// XML => JSON and JSON => XML
const { XMLParser, XMLBuilder } = require('fast-xml-parser');
const parser = new XMLParser
// Read files
const { readFile } = require('fs')

// This takes XML from req.body and stores it to MongoDB
// This works
const createOrderFromXML = async (req, res, next) => {
  // Check that body has data
  if (Object.keys(req.body).length === 0) {
    // If no data throw error
    throw new APIError('No data in body', StatusCodes.BAD_REQUEST)
  }
  // If body has data store it to variable
  let JSONOrder = req.body        
  console.log(JSONOrder)
  // Try catch for error handling
  try {
    // Asyncronic call to create a new Order to MongoDB
    await Order.create(JSONOrder)
    res.status(StatusCodes.CREATED).json(JSONOrder)
  } catch (err) {
    next(err)
  }  
}

// This controller returns all orders stored in database
// This works
const getAllOrders = async (_req, res, _next) => {
  const orders = await Order.find({})
  console.log(orders)
  if (orders.length === 0) throw new APIError('No orders in database', StatusCodes.NOT_FOUND)
  res.status(StatusCodes.OK).json(orders)  
}

// This controller returns all orders that are marked as open
// This works
const getOpenOrders = async (_req, res, _next) => {
  const queryObject = {}
  queryObject.order_status = "In collection"
  const orders = await Order.find({'order.order_status': 'Open'})
  console.log(orders)
  if (orders.length === 0) throw new APIError('No open orders in database', StatusCodes.NOT_FOUND)
  res.status(StatusCodes.OK).json(orders)  
}

// This controller returns an order by id
const getOrderById = async (req, res) => {
  const idOfOrder = req.params.id
  const order = await Order.findById(idOfOrder)
  if (!order) throw new APIError(`No orders with id ${idOfOrder}`, StatusCodes.NOT_FOUND)
  res.status(StatusCodes.OK).json(order)
}

// This controller is used to change the state of an order 
// (Open => In Collection).
// Use this controller when user selects an order for collecting
// This works
const collectingStarted = async (req, res) => {
  console.log(req.params.id)   
  const idOfOrder = req.params.id  
  const newInformation = req.body 
  const editedOrder = await Order.findByIdAndUpdate(idOfOrder, newInformation, { runValidators: true })
  // If no document is found throw new APIError
  if (!editedOrder) throw new APIError(`No orders with id ${idOfOrder}`, StatusCodes.NOT_FOUND)

  // Let's create information for email
  const recipient = newInformation.order.email
  const emailHeader = 'Keräily on aloitettu'
  const emailText = `
    Terve ${newInformation.order.customer}!
    
    Tilauksesi keräily on aloitettu
    
    Ystävällisin terveisin
    Verkkokauppa
    `

  // Call sendEmail middleware with email information
  sendEmail(recipient, emailHeader, emailText)

  // Respond that request was succesfull if document is found with
  // provided id.
  res.status(StatusCodes.OK).json({
    success: true,
    message: `Order updated!`
  })
}

// This controller is used to edit documents stored in MongoDB
// Use this controller to update each item that is collected
// This works
const editOrder = async (req, res) => {
  console.log(req.params.id)   
  const idOfOrder = req.params.id  
  const newInformation = req.body 
  const editedOrder = await Order.findByIdAndUpdate(idOfOrder, newInformation, { runValidators: true })
  // If no document is found throw new APIError
  if (!editedOrder) throw new APIError(`No orders with id ${idOfOrder}`, StatusCodes.NOT_FOUND)
  // Respond that request was succesfull if document is found with
  // provided id.
  res.status(StatusCodes.OK).json({
    success: true,
    message: `Order updated!`
  })
}

// This controller is used to receive a fully collected order
// Use this controller when user confirms that collecting is complete
// This still needs connection to freight API
const collectedOrder = async (req, res) => {
  const idOfOrder = req.params.id  
  const newInformation = req.body 
  const editedOrder = await Order.findByIdAndUpdate(idOfOrder, newInformation, { runValidators: true })
  // If no document is found throw new APIError
  if (!editedOrder) throw new APIError(`No orders with id ${idOfOrder}`, StatusCodes.NOT_FOUND)  
  
  // Let's create information for email
  const recipient = newInformation.order.email
  const emailHeader = 'Keräily on suoritettu'
  const emailText = `
    Terve ${newInformation.order.customer}!
    
    Tilauksesi keräily on suoritettu.

    Saat hetken kuluttua rahtiyhtiöltä viestin, jossa on tilauksesi seurantakoodi.
    
    Kiitos tilauksesta!

    Ystävällisin terveisin
    Verkkokauppa
    `

  // Call sendEmail middleware with email information
  sendEmail(recipient, emailHeader, emailText)

  // Respond that request was succesful if document is found with
  // provided id.
  res.status(StatusCodes.OK).json({
    success: true,
    message: `Order updated!`
  })
}

// This controller is used if all the items in order can't be found
// Use this route if something can't be found from warehouse
const itemsMissing = (req, res) => {
  const idOfOrder = req.params.id  
  const newInformation = req.body
}

module.exports = {
  createOrderFromXML,
  getAllOrders,
  getOpenOrders,
  getOrderById,
  editOrder,
  collectingStarted,
  collectedOrder,
  itemsMissing
}