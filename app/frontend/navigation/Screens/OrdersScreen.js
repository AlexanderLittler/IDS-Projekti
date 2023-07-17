import React from 'react';

// Styles
import { Box, Text } from 'native-base';
import { styles } from '../../styles/Navigation';

// Data test 
import data from '../../data/orders.json';

const OrdersScreen = () => {
  return (
    <Box style={styles.container}>
        // Mapping data from test json file
      {data.orders.map((order) => (
        <Box key={order.id} style={[styles.card, { width: '76%' }]}>
          <Text style={styles.cardTitle}>{order.title}</Text>
        </Box>
      ))}
    </Box>
  );
};

export default OrdersScreen;
