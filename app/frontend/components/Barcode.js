import { useState, useRef } from 'react';
import { Button, Keyboard, StyleSheet, Text, TextInput, View } from 'react-native';

const Barcode = () => {
  // Decleare a variable for storing a barcode 
  const [barcode, changeBarcode] = useState('')
  // Create a reference to be used in TextInput component that
  // receives the barcode
  const barcodeRef = useRef()

  // This handles 'Lue viivakoodi'-Button press
  const readBarcode = () => {
    // Focus on TextInput component
    barcodeRef.current.focus()
    // Clear TextInput component
    barcodeRef.current.clear()
    // Empty old barcodes stored in state
    changeBarcode('')
  }

  // This handles TextInput component for barcode reading
  const barcodeChanger = (barcode) => {
    changeBarcode(barcode)
  }

  return (
    // Zebra DataWedge sends barcodes as keystrokes. So we need
    // to have something to receive these keystokes. This is done
    // by TextInput component. TextInput component needs to have focus
    // in order to receive keystrokes. This is achieved by 
    //'Lue viivakoodi'-button that put's focus on TextInput component.
    <View style={styles.container}>
      <TextInput 
        style={styles.barcode}
        ref={barcodeRef}
        onFocus={Keyboard.dismiss}
        onChangeText={(barcode) => barcodeChanger(barcode)}
      />
      <Button 
        title='Lue viivakoodi'
        onPress={readBarcode}
      />
      <Text>Viivakoodi on: {barcode}</Text>
    </View>
  );
}

export default Barcode

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  barcode: {
    height: 40,
    width: 300,
    margin: 12,
    borderWidth: 1,
    padding: 10,
  }
});
