from flask import Flask, jsonify, request, abort
from cryptography.fernet import Fernet
import os
import hmac
import mysql.connector

app = Flask(__name__)

key = os.getenv("ENCRYPTION_KEY").encode()
cipher_suite = Fernet(key)

def verify_request(secret, headers):
        received_secret = headers.get('x-api-key')
        if not received_secret:
                app.logger.warning(f'No API key provided from {headers.get("x-forwarded-for")}') 
                abort(401)
        else:
                received_secret = received_secret.encode()
        if not hmac.compare_digest(received_secret, secret):
                app.logger.warning(f'Invalid API key from {headers.get("x-forwarded-for")}')
                abort(401)

def fetch_key(name):
        connection = mysql.connector.connect(
                host=os.getenv("MARIADB_HOST"),
                user=os.getenv("MARIADB_USER"),
                password=os.getenv("MARIADB_PASSWORD"),
                database=os.getenv("MARIADB_DATABASE")
        )
        cursor = connection.cursor()
        query = "SELECT api_key FROM api_keys WHERE name = %s"
        cursor.execute(query, (name,))
        result = cursor.fetchone()
        connection.close()
        if result:
                return cipher_suite.decrypt(result[0])
        return "nothing"

@app.route('/place', methods=['GET', 'POST'])
def place():
        verify_request(fetch_key("place"), request.headers)
        if request.method == 'GET':
                return jsonify({'success':'success'})

@app.errorhandler(404)
def page_not_found(e):
        return jsonify({'error': 'Unknown route'}), 404

if __name__ == '__main__':
        app.run(debug=False, host='192.168.100.30')
