import React, { useState } from 'react';
import { View, TextInput, Button, TouchableOpacity, Text } from 'react-native';
import styles from './styles';
//import { AntDesign } from '@expo/vector-icons';

const Register = () => {
  const [nimi, setNimi] = useState('');
  const [email, setEmail] = useState('');
  const [salasana, setSalasana] = useState('');
  const [salasana2, setSalasana2] = useState('');

  const handleRegister = () => {
    const user = {
      nimi: nimi,
      email: email,
      salasana: salasana,
      salasana2: salasana2,
    };

    console.log(user); // Tässä vaiheessa voit lähettää käyttäjätiedot palvelimelle tai suorittaa muut tarvittavat toiminnot.
  };

  const handleBackButton = () => {
    // Lisää tässä tarvittavat toiminnot takaisinpaluunapin painallukselle
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={handleBackButton} style={styles.backButton}>
          <Text style={styles.headerTitle}>{'<'}</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Rekisteröidy</Text>
      </View>

      <TextInput
        placeholder="Nimi"
        value={nimi}
        onChangeText={text => setNimi(text)}
        style={styles.input}
      />
      <TextInput
        placeholder="Email"
        value={email}
        onChangeText={text => setEmail(text)}
        keyboardType="email-address"
        style={styles.input}
      />
      <TextInput
        placeholder="Salasana"
        value={salasana}
        onChangeText={text => setSalasana(text)}
        secureTextEntry
        style={styles.input}
      />
      <TextInput
        placeholder="Salasana uudelleen"
        value={salasana2}
        onChangeText={text => setSalasana2(text)}
        secureTextEntry
        style={styles.input}
      />

      <Button
        title="Tallenna"
        onPress={handleRegister}
        color="#02718D"
      />
    </View>
  );
};

export default Register;
