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

    if 'username' not in data:
        return jsonify({'message': 'username field is mandatory'})

    if 'password' not in data:
        return jsonify({'message': 'password field is mandatory'})

    if 'email' not in data:
        return jsonify({'message': 'email field is mandatory'})

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

    if 'username' not in data:
        return jsonify({'message': 'username field is mandatory'})

    if 'password' not in data:
        return jsonify({'message': 'password field is mandatory'})

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

    added = False
    conn = get_db()
    cur = conn.cursor()

    if 'password' in data:
        added = True
        hashed_password = generate_password_hash(data['password'], method='sha256')

        cur.execute('UPDATE users SET password = ? WHERE username = ?',
                    (hashed_password, current_user))

    if 'email' in data:
        cur.execute('UPDATE users SET email = ? WHERE username = ?',
                    (data['email'], current_user))
        added = True

    if 'discogs_token' in data:
        cur.execute('UPDATE users SET discogs_token = ? WHERE username = ?',
                    (data['discogs_token'], current_user))
        added = True

    if not added:
        conn.close()
        return jsonify({'message': 'At least one field should be updated'})

    conn.commit()
    conn.close()

    # Return a success message
    return jsonify({'message': 'User updated successfully'})


@app.route('/profile/<username>', methods=['POST'])
@jwt_required()
def profile(username):
    current_user = get_jwt_identity()
    user_to_display = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

    if user_to_display is None:
        return jsonify({'message': 'There is no user with this username'})

    if username != current_user:
        return jsonify({'userData': {
            'email': user_to_display['email'],
            'username': user_to_display['username']
        }})

    return jsonify({'userData': {
        'email': user_to_display['email'],
        'username': user_to_display['username'],
        'discogs_token': user_to_display['discogs_token']
    }})


@app.route('/playlists', methods=['POST'])
@jwt_required()
def create_playlist():
    current_user = get_jwt_identity()
    playlist_content = request.data.decode()
    insert_db('playlists', ('playlist_content', 'user_id',), (playlist_content, current_user, ))
    return 'Playlist created', 201


@app.route('/playlists/<int:playlist_id>', methods=['GET'])
@jwt_required()
def get_playlist(playlist_id):
    current_user = get_jwt_identity()
    playlist = query_db('SELECT playlist_content FROM playlists WHERE playlist_id = ? AND user_id = ?',
                        (playlist_id, current_user), one=True)
    if playlist:
        return playlist['playlist_content'], 200
    else:
        return 'Playlist not found', 404


if __name__ == '__main__':
    app.run()
