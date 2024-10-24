# Shajira Guzman

import unittest
from server import app, deserializeKey  # importing app from server.py
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class TestApp(unittest.TestCase):

    # client for the flask application
    def setUp(self):

        self.app = app.test_client()
        self.app.testing = True 


    # test the JWKS endpoint
    def testEndpoint(self):

        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)  # checks for OK response
        json_data = json.loads(response.data)        # convert to JSON


    # test the auth endpoint with valid parameters
    def testAuthValid(self):

        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)  # checks for OK response
        json_data = json.loads(response.data) 
        self.assertIn('token', json_data)            # checks for token


    # test the auth endpoint with expired parameters
    def testAuthExpired(self):

        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data)
        self.assertIn('token', json_data)  


    # test deserialization of a valid private key
    def testDeserializeValidKey(self):

        privateKey = rsa.generate_private_key(              # generate private key and set variables
            key_size = 2048,
            public_exponent = 65537,
            backend = default_backend()
        )
        # convert to PKCS#1 PEM
        PKCSpem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.NoEncryption()  
        )

        deserializedKey = deserializeKey(PKCSpem)
        self.assertIsNotNone(deserializedKey)
        self.assertTrue(isinstance(deserializedKey, rsa.RSAPrivateKey))


    # test deserialization with invalid key data
    def testDeserializeInalidKey(self):

        invalidKey = b"not a valid key"
        deserializedKey = deserializeKey(invalidKey)
        self.assertIsNone(deserializedKey)


if __name__ == '__main__':
    app.run(port=8080)