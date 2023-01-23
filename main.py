import sqlite3

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Set up Flask-JWT
jwt = JWTManager(app)


def get_db():
    conn = sqlite3.connect(app.config['DATABASE_URI'])
    conn.row_factory = sqlite3.Row
    return conn


def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv


def insert_db(table, fields=(), values=()):
    conn = get_db()
    cur = conn.cursor()
    query = 'INSERT INTO %s (%s) VALUES (%s)' % (
        table,
        ', '.join(fields),
        ', '.join(['?'] * len(values))
    )
    cur.execute(query, values)
    conn.commit()
    conn.close()


@app.route('/register', methods=['POST'])
def register():
    # Get the form data
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    # Hash the password for security
    hashed_password = generate_password_hash(password, method='sha256')

    # Save the user to the database
    insert_db('users', ('username', 'password', 'email'), (username, hashed_password, email))

    # Return a success message
    return jsonify({'message': 'User created successfully'})


@app.route('/login', methods=['POST'])
def login():
    # Get the form data
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if the user exists in the database
    user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
    if user is not None:

        # Check if the password is correct
        if check_password_hash(user['password'], password):
            # Create a JWT token
            access_token = create_access_token(identity=username)
            # Return the token
            return jsonify({'message': 'Login successful', 'access_token': access_token})

        # If the username or password is incorrect, return an error message
    return jsonify({'error': 'Invalid username or password'})


@app.route('/edit', methods=['POST'])
@jwt_required()
def edit():
    # Get the current user's username
    current_user = get_jwt_identity()

    # Get the form data
    data = request.get_json()
    password = data['password']
    email = data['email']

    # Hash the password for security
    hashed_password = generate_password_hash(password, method='sha256')

    # Update the user's password in the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET password = ?, email = ? WHERE username = ?', (hashed_password, email, current_user))
    conn.commit()
    conn.close()

    # Return a success message
    return jsonify({'message': 'User updated successfully'})


if __name__ == '__main__':
    app.run()
