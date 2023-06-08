const express = require('express')
const app = express()
// XML => JSON and JSON => XML
const { XMLParser, XMLBuilder } = require('fast-xml-parser');
const parser = new XMLParser
// Read files
const { readFileSync } = require('fs')
const morgan = require('morgan')

// orders from a JSON-file
//const { orders } = require('./data/orders')

// orders from an XML-file
const xmlOrders = readFileSync('./data/orders.xml')
// parse XML order to JSON-object
let jsonOrders = parser.parse(xmlOrders)

PORT = 3000

app.use(express.static('./public'))
app.use(express.json())
// Logger middleware
app.use(morgan('combined'))

// Frontpage with some text
app.get('/', (req, res) => {
  res.status(200).send('Backend for IDS collector app.')
})

// Route that serves all open orders
app.get('/api/openOrders', (req, res) => {
  // use this if data is received in XML
  res.json(jsonOrders)
  // use this if data is receiced as JSON
  //res.json(orders)
})

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`)
})