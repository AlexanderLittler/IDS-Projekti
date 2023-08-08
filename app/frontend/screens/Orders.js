import React from 'react';
import { useState, useEffect } from 'react';
import { Flex, ScrollView, Text } from 'native-base';

// Components
import Card from '../components/Card/Card';

const OrdersScreen = ({ navigation }) => {
  const [isLoading, setLoading] = useState(true);
  const [openOrders, setOpenOrders] = useState({});

  // get IPv4 for your Windows machine:
  //      - start terminal and type 'ipconfig'  
  const computerIPv4 = '192.168.97.125'
  
  // fetch data asynchronously from backend
  const getOpenOrders = async () => {
    await fetch('http://' + computerIPv4 + ':3000/api/getOpenOrders/')
    .then(res => res.json())
    .then(json => setOpenOrders(json))    
    .catch(error => console.log(error))
    .finally(() => setLoading(false))    
  }

  useEffect(() => {
    // Let's add a listener for focus on this screen to force render
    navigation.addListener('focus', () => {
      setLoading(true)
      getOpenOrders()
    })    
  }, [])


  if (isLoading === true) {
    return (
      <Flex>
        <Text>Ladataan</Text>
      </Flex>
    )
  }
  
  if (isLoading === false) {    
    return (
      <ScrollView>
        <Flex>
          {openOrders.map((order) => (          
            <Card 
              key={order._id} 
              title={order.order.customer} 
              content={'tilausnumero: ' + order.order.order_id}
              onPress={async () => {
                let orderID = order._id
                // Change order status to 'In collection'
                order.order.order_status = 'In collection'
                // Create PUT request
                const requestOptions = {
                  method: 'PUT',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(order)
                };
                // Make a PUT request to backend to update 
                // order status 'Open' => 'In collection'
                await fetch('http://' + computerIPv4 + ':3000/api/editOrder/' + orderID, requestOptions)
                  .then(res => res.json())
                  
                // Navigate to 'Collecting' screen with orderID in props.
                navigation.navigate('Collecting', { orderID: {orderID} })
              }}
            >
            </Card>
            )
          )}
        </Flex>
      </ScrollView>
    );
  }
};

export default OrdersScreen;
