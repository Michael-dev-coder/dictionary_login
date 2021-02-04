import os
import secrets
import webbrowser
from PIL import Image
from flask import render_template, url_for, flash, redirect, request
from Tech_know_dictionary import app, db, bcrypt, mail
from Tech_know_dictionary.forms import RegistrationForm, LoginForm, WordForm, UpdateAccountForm, RequestResetForm, RestPasswordForm
from Tech_know_dictionary.models import User, Post
import re
import nltk
from Tech_know_dictionary.utils import web_get_records, get_suggestions
from flask_login import login_user, current_user, logout_user, login_required
from Tech_know_dictionary.text_to_speech import text_to_speech
from flask_mail import Message

try:
    nltk.data.find("corpora/wordnet")
except LookupError:
    nltk.download("wordnet")


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    match_item_number = re.compile(r"\d+\.")
    form = WordForm()
    word = " "
    if form.validate_on_submit():
        word = form.word.data
        resp = web_get_records(word)
        words = []
        suggestions = []

        if resp:
            resp = match_item_number.sub("", resp).strip().split("\n")
            loop_index = -1
            match_usage_item_letter = re.compile(r"^\w+\.")

            for res in resp:
                if "-" in res and " " not in res:
                    pos = res.split("-")
                    words.append({"part_of_speech": pos[0], "value": pos[1]})
                    loop_index += 1
                elif "Definition" in res:
                    words[loop_index]["definition"] = res.replace("Definition : ", "")
                elif match_usage_item_letter.search(res):
                    if "usage" not in words[loop_index]:
                        words[loop_index]["usage"] = []

                    words[loop_index]["usage"].append(res)
        else:
            suggestions = get_suggestions(word)
            if len(suggestions) >= 0:
                text_to_speech("Word not found on our database, Here is what I found on Google.")
                url = 'https://google.com/search?q=' + word
                webbrowser.get().open(url)

        return render_template(
            "home.html",
            title="Dictionary",
            form=form,
            resp=words,
            found=len(words) >= 1,
            suggestions=suggestions[:5] if len(suggestions) > 5 else suggestions,
            text_to_speech=text_to_speech(resp)
        )
    return render_template('home.html', title='Home', form=form, resp=[], found=True, suggestions=[])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful, Please check your email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password , visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password', 'success')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>.', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = RestPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)
