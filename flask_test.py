from bson import ObjectId
from datetime import datetime
from flask import Flask, abort, render_template, url_for, flash , redirect , request, jsonify, session, current_app
from pymongo import MongoClient
import string
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user , current_user , UserMixin, logout_user
from bson import ObjectId
import os
from math import ceil
from flask_paginate import Pagination, get_page_args

from itsdangerous import URLSafeTimedSerializer as Serializer
from itsdangerous import Signer, BadSignature, SignatureExpired
from flask_mail import Mail, Message
import secrets
import time
import logging
import json




with open('/etc/flaskblog_config.json') as config_file:
    config = json.load(config_file)

# Configure logging
logging.basicConfig(level=logging.INFO)


UPLOAD_FOLDER = r'/home/kirito/GIT_REPO/test/static/profile_pics'
client = MongoClient('mongodb://localhost:27017/')
db = client['DB']
users = db['users']
posts = db['posts']

app = Flask(__name__)

# new_secret_key = secrets.token_hex(16)  # Generate a 32-character random hexadecimal string
# app.config['SECRET_KEY'] = new_secret_key
app.config['SECRET_KEY'] = config.get('SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = config.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = config.get('MAIL_PASSWORD')
mail = Mail(app)

bcrypt = Bcrypt(app)

signer = Signer(app.config['SECRET_KEY'])



login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
"""
posts = [
    {
        'author' : 'Eldsouky',
        'title' : 'code1',
        'content': 'Flask'

    },
    {
        'author' : 'omar',
        'title' : 'code2',s
        'content': 'OCR'
    }


]

"""

class User(UserMixin):
    def __init__(self, user_id, username, email):
        self.id = user_id
        self.username = username
        self.email = email



    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        user_id_str = str(self.id)  # Convert ObjectId to string
        print("User ID:", user_id_str)
        print("Secret Key:", app.config['SECRET_KEY'])
        # print(s.dumps({'user_id': user_id_str}))
        return s.dumps({'user_id': user_id_str})

    # def get_reset_token(self, expires_sec=900000):
    #     s = Serializer(app.config['SECRET_KEY'], expires_sec)
    #     _id_str = str(self.id)  # Convert ObjectId to string
    #     salt = hashlib.sha256(str(int(time.time())).encode('utf-8')).hexdigest()
    #     return s.dumps({'user_id': _id_str})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            print("Token:", token)
            # Load the token and extract the user_id
            data = s.loads(token, max_age=9000000)  # 15 minutes (900 seconds)
            print("Data:", data)
            user_id = data.get('user_id')
            # Find the user using the extracted user_id
            return users.find_one({'_id': ObjectId(user_id)})
        except SignatureExpired:
            # Token has expired
            print("Token expired:", token)
            return None
        except BadSignature:
            # Token is invalid
            print("Invalid token:", token)
            return None



@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


# Implement the load_user function
@login_manager.user_loader  
def load_user(user_id):
    user_data = users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_id, user_data['username'], user_data['email'])
    return None



# @login_manager.user_loader
# def load_user(user_id):
#     # Assuming your user object has an attribute 'id' which stores the user's ID
#     user_data = users.find_one({'_id': user_id})
#     print(user_data)
#     if user_data:
#          user = User(user_data['_id'], user_data['username'], user_data['email'])
#         return user
#     return None



# Define page size for pagination
page_size = 2

@app.route("/")
def home():
    # Get current page number from request
    page_number = request.args.get('page', 1, type=int)

    # Calculate skip value based on page number
    skip = (page_number - 1) * page_size

    # Retrieve posts from the database with pagination
    total_posts = posts.count_documents({})
    total_pages = -(-total_posts // page_size)  # Ceiling division
    Posts = list(posts.find().skip(skip).limit(page_size).sort('date_posted', -1))

    # Ensure each post object includes the user image URL
    for post in Posts:
        user_data = users.find_one({'username': post['author']})
        if user_data:
            post['user_image'] = url_for('static', filename='profile_pics/' + user_data['username'] + '.jpg')
        else:
            post['user_image'] = url_for('static', filename='profile_pics/default.jpg')

    # Create pagination object
    pagination = Pagination(page=page_number, total=total_posts, per_page=page_size, css_framework='bootstrap4')

    return render_template('home.html', title='home', posts=Posts, pagination=pagination)



@app.route("/creator")

@app.route("/mems")
def about():
    return render_template('about.html', title='creator' )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = bcrypt.generate_password_hash(password).decode('utf-8')
        confirm_password = request.form['confirm-password']
        email = request.form['email']
        user = users.find_one({'username': username, 'email': email})
        # print(bool(user))
        if len(username) < 3 or len(username) > 30:
            flash('Username must be between 3 and 30 characters long', 'danger')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('register'))
        elif not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit', 'danger')
            return redirect(url_for('register'))
        elif not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect(url_for('register'))
        elif not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect(url_for('register'))
        elif not any(char in string.punctuation for char in password):
            flash('Password must contain at least one special character', 'danger')
            return redirect(url_for('register'))  
        
        if user :
            flash('Username and Email already exists', 'danger')
            return redirect(url_for('login'))


        users.insert_one({'username': username, 'password': password2, 'email': email})
        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('login'))
   
    return render_template('register.html', title='register')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))   
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.find_one({'username': username})
        # print (user)
        if user and bcrypt.check_password_hash(user['password'], password):
            next_page = request.args.get('next')
            print(user['_id'])
            user_obj = User(user['_id'], username, email= ['email'])  # Pass username here
            login_user(user_obj)
            # load_user(user['_id'])
            flash('Login successful', 'success')
            return redirect(next_page) if next_page else redirect (url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html', title='Login')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        picture = request.files['picture']
        if picture:
            # Delete the old profile picture if it exists
            old_picture_path = os.path.join(UPLOAD_FOLDER, current_user.username + '.jpg')
            if os.path.exists(old_picture_path):
                # Save the name of the old picture
                old_picture_name = current_user.username + '.jpg'
                # Get the number of photos for the user
                photo_count = len([name for name in os.listdir(UPLOAD_FOLDER) if name.startswith(current_user.username)])
                # Rename the old picture with a number suffix
                new_picture_name = f"{current_user.username}_{photo_count}.jpg"
                new_picture_path = os.path.join(UPLOAD_FOLDER, new_picture_name)
                os.rename(old_picture_path, new_picture_path)
                # Update the user's profile picture name in the database
                users.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'profile_pic': new_picture_name}})
            old_picture_path = os.path.join(UPLOAD_FOLDER, current_user.username + '.jpg')
            if os.path.exists(old_picture_path):
                os.remove(old_picture_path)
            picture.save(os.path.join(UPLOAD_FOLDER, current_user.username + '.jpg'))
        print("Current User ID:", current_user.id)
        try:
            # Convert current_user.id to ObjectId
            user_id = ObjectId(current_user.id)
            result = users.update_one({'_id': user_id}, {'$set': {'username': username, 'email': email}})
            print("Modified Count:", result.modified_count)
            if result.modified_count == 1:
                print("Account Updated Successfully")
                flash('Your account has been updated!', 'success')
            else:
                print("Failed to update account: User ID not found")
                flash('Failed to update account: User ID not found', 'danger')
        except Exception as e:
            print("Failed to update account:", e)
            flash('Failed to update account: Internal error', 'danger')
        
        # Update the image file name to new username if username is updated
        if result.modified_count == 1:
            static_folder = app.static_folder
            profile_pics_folder = os.path.join(static_folder, 'profile_pics')
            old_image_path = os.path.join(profile_pics_folder, current_user.username + '.jpg')
            new_image_path = os.path.join(profile_pics_folder, username + '.jpg')
            try:
                os.rename(old_image_path, new_image_path)
            except FileNotFoundError:
                print("File not found:", old_image_path)
                # Handle the error as required, such as logging or displaying a message to the user
        
        print("New Account Information:", current_user.id, username, email)
        return redirect(url_for('account'))
    
    image_file = url_for('static', filename='profile_pics/' + current_user.username + '.jpg')
    return render_template('account.html', title='Account', current_user=current_user, image_file=image_file)


@app.route("/post/new", methods=['GET', 'POST'])
def new_post():
       # Generate a CSRF token and store it in the session
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if title and content:
            current_date = datetime.utcnow()  # Get the current date and time
            posts.insert_one({'author': current_user.username, 'title': title, 'content': content, 'date_posted': current_date})
            flash('Your post has been created!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Title and Content are required', 'danger')
            return redirect(url_for('new_post'))
        # flash('Your post has been created!', 'success')

        # return redirect(url_for('home'))
    
    # posts.append({'author': current_user.username, 'title': title, 'content': content})


    return render_template('create_post.html', title='New Post',  legend='New Post')

@app.route("/post/<post_id>", methods=['GET'])
def post(post_id):
    Post = posts.find_one({'_id': ObjectId(post_id)})
    print(post_id)
    if Post:
        user_data = users.find_one({'username': Post['author']})
        if user_data:
            Post['user_image'] = url_for('static', filename='profile_pics/' + user_data['username'] + '.jpg')
        else:
            Post['user_image'] = url_for('static', filename='profile_pics/default.jpg')
    return render_template('post.html', title='post', post=Post)


@app.route("/post/<post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    print("Post ID:", post_id)
    post = posts.find_one({'_id': ObjectId(post_id)})
    if post['author'] != current_user.username:
        abort(403)

    if request.method == 'POST':
        new_title = request.form['title']
        new_content = request.form['content']
        if new_title and new_content:
            current_date = datetime.utcnow()
            posts.update_one({'_id': ObjectId(post_id)}, {'$set': {'title': new_title, 'content': new_content, 'date_posted': current_date}})
            flash('Your post has been updated!', 'success')
            return redirect(url_for('post', post_id=post_id))
        else:
            flash('Title and Content are required', 'danger')
            return redirect(url_for('update_post', post_id=post_id))

    return render_template('create_post.html', title='Update Post', legend='Update Post', post=post, new_title=post['title'], new_content=post['content'])


@app.route("/post/<post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    print("Post ID:", post_id)
    # Your code to delete the post goes here
    post = posts.find_one({'_id': ObjectId(post_id)})
    print(current_user.username)
    if post['author'] != current_user.username:
        abort(403)
    if request.method == 'POST':
        posts.delete_one({'_id': ObjectId(post_id)})
        flash('Your post has been deleted!', 'success')
        return redirect(url_for('home'))
    
    return render_template('post.html', title='Delete Post', post=post)




@app.route("/user/<username>")
def user_posts(username):
    # Check if the user exists
    print(username)
    user = users.find_one({'username': username})
    print(user)
    if not user:
        abort(404)  # User not found, return 404 error

    # Get current page number from request
    page_number = request.args.get('page', 1, type=int)

    # Calculate skip value based on page number
    skip = (page_number - 1) * page_size

    # Retrieve posts from the database with pagination
    total_posts = posts.count_documents({'author': username})
    total_pages = ceil(total_posts / page_size)  # Calculate total pages
    Posts = list(posts.find({'author': username}).skip(skip).limit(page_size))

    # Ensure each post object includes the user image URL
    for post in Posts:
        user_data = users.find_one({'username': post['author']})
        if user_data:
            post['user_image'] = url_for('static', filename='profile_pics/' + user_data['username'] + '.jpg')
        else:
            post['user_image'] = url_for('static', filename='profile_pics/default.jpg')

    # Create pagination object
    pagination = Pagination(page=page_number, total=total_posts, per_page=page_size, css_framework='bootstrap4')

    return render_template('user_posts.html', title='User Posts', posts=Posts, pagination=pagination, user=user)



def send_reset_email(user_data):
    user = User(user_data['_id'], user_data['username'], user_data['email'])
    print(user.email)
    token = user.get_reset_token()
    print(token)
    msg = Message('Password Reset Request', sender='omareldsouky14@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''

    try:
        mail.send(msg)
        logging.info(f"Password reset email sent to {user.email}")
        return True  # Indicate success
    except Exception as e:
        logging.error(f"Error sending password reset email to {user.email}: {str(e)}")
        return False  # Indicate failure

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        
        if user:
            if send_reset_email(user):
                flash('An email has been sent with instructions to reset your password', 'info')
            else:
                flash('An error occurred while sending the password reset email. Please try again later.', 'danger')
        else:
            flash('No user found with that email address', 'danger')
        
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password')



@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
        
    print("Token:", token)

    if request.method == 'POST':
        # username = request.form['username']
        password = request.form['password']
        password2 = bcrypt.generate_password_hash(password).decode('utf-8')
        confirm_password = request.form['confirm-password']
        email = user['email']
        # user = users.find_one({'username': username, 'email': email})
        # print(bool(user))
        # if len(username) < 3 or len(username) > 30:
        #     flash('Username must be between 3 and 30 characters long', 'danger')
        #     return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token
        elif len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token
        elif not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token
        elif not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token
        elif not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token
        elif not any(char in string.punctuation for char in password):
            flash('Password must contain at least one special character', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token  
        
        if bcrypt.check_password_hash(user['password'], password):
            flash('You entered the same old Passord', 'danger')
            return redirect(url_for('reset_token', token=token))  # Redirect to reset_token


        users.update_one({'email': email}, {'$set': {'password': password2}})
        flash(f'Password changed for {email}!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', title='Reset Password')


if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
