# Shajira Guzman

from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import jwt
import base64
import sqlite3

# generate flask app
app = Flask(__name__)

# store keys with their exp time
keys = {}


def createDatabase():
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        connection.commit()
        print("Table created successfully or already exists.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    connection.close()

createDatabase()


# generate RSA key pairs
def generate_rsa_key():

    print("Starting Key generation")
    expired = request.args.get('expired')               # get expiration (true or false) from request

    privateKey = rsa.generate_private_key(              # generate private key and set variables
        key_size = 2048,
        public_exponent = 65537,
        backend = default_backend()
    )

    kid = str(len(keys) + 1)  

    if expired:
        expirationTime = int((datetime.utcnow() - timedelta(hours=5)).timestamp())#expirationTime = datetime.utcnow() - timedelta(days=1)  # set exp a day behind
    else:
        expirationTime = int((datetime.utcnow() + timedelta(hours=2)).timestamp())#expirationTime = datetime.utcnow() + timedelta(days=5)  # set exp to expire in 5 days

    # convert to PKCS#1 PEM
    PKCSpem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption()  
    )

    #store key in database
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', 
              (PKCSpem, expirationTime))
        connection.commit()
        print("Keys stored in database")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    connection.close()

    return kid


# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():

    print("start jwks endpoint")
    jwksKeys = []

    #get private keys from database
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()
    cursor.execute('SELECT kid, key, exp FROM keys')
    rows = cursor.fetchall()
    connection.close()



    currentTime = int(datetime.utcnow().timestamp())

    # iterate over keys and store non expired keys
    for row in rows:
        kid, pk, exp = row
        privateKey = deserializeKey(pk) #deserialize key for public key generation
        if currentTime < exp:
            # Load the public key from the private key
            publicKey = privateKey.public_key()  
            n = publicKey.public_numbers().n.to_bytes((publicKey.public_numbers().n.bit_length() + 7) // 8, byteorder='big')
            e = publicKey.public_numbers().e.to_bytes((publicKey.public_numbers().e.bit_length() + 7) // 8, byteorder='big')
            
            # Add key details to JWKS
            jwksKeys.append({
                "kid": str(kid),
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig", 
                "n": base64.urlsafe_b64encode(n).rstrip(b'=').decode('utf-8'), 
                "e": base64.urlsafe_b64encode(e).rstrip(b'=').decode('utf-8')
            })
        #else:
            #print("found expired key!!")
    return jsonify({"keys": jwksKeys})



def deserializeKey(data):

    if isinstance(data, str):
        data = data.encode('utf-8')  # Convert to bytes
    try:
        privateKey = serialization.load_pem_private_key(
            data,
            password=None,  
            backend=default_backend()
        )
        return privateKey
    except ValueError as e:
        print(f"Error loading private key: {e}")
        return None
  


#return a private key from database
def getKey(kid):

    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('SELECT key FROM keys WHERE kid = ?', (kid,))
        row = cursor.fetchone()
        print("found data in database!")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    connection.close()
    if row:
        return row[0]  # returns key as a blob
    return None




@app.route('/auth', methods=['POST'])
def authenticate():

    print("start auth")
    expired = request.args.get('expired')
    print("expired: ", expired)

    # set exp time to 5 hours behind or two hours later
    if expired:
        print("got an expired key")
        expirationTime = int((datetime.utcnow() - timedelta(hours=5)).timestamp())#expirationTime = datetime.utcnow() - timedelta(days=1)
    else: 
        expirationTime = int((datetime.utcnow() + timedelta(hours=2)).timestamp())#expirationTime = datetime.utcnow() + timedelta(hours=5)
    
    print(expirationTime)
    kid = generate_rsa_key()
    privateKey = getKey(kid)
    if privateKey is None:
        return jsonify({"error": "Private key not found"}), 404
    
    
    pk = deserializeKey(privateKey)     #deserialize the private key


    payload = {'username': 'tempUser', 'exp': expirationTime}
    token = jwt.encode(payload, pk, algorithm='RS256', headers={'kid': kid})

    return jsonify(token=token)


if __name__ == '__main__':
    app.run(port=8080)
