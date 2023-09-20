from flask import Flask, render_template, redirect, url_for, flash, make_response, request
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime, date
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap5(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///posts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('BOOL')
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

ckeditor = CKEditor(app)
app.config['CKEDITOR_SERVE_LOCAL'] = True 


# CONFIGURE TABLE
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class  Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # Required for Flask-Login
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
 
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

    
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    author = StringField("Author", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Create Post")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Log In")



with app.app_context():
    db.create_all()

@app.route('/')
def get_all_posts():
    page = request.args.get('page', default=1, type=int)
    per_page = 3  
    offset = (page - 1) * per_page
    has_more_posts = len(BlogPost.query.all()) > page * per_page
    with app.app_context():
        posts = BlogPost.query.order_by(BlogPost.date.desc()).offset(offset).limit(per_page).all()
        posts_list = [{
            "id": post.id,
            "title": post.title,
            "subtitle": post.subtitle,
            "date": datetime.strptime(post.date, '%B %d, %Y').strftime('%B %d, %Y'),  # Convert and format the date            
            "body": post.body,
            "author": post.author,
            "img_url": post.img_url,
        } for post in posts]

    return render_template("index.html", all_posts=posts_list, page=page, has_more_posts=has_more_posts)



@app.route('/post/<int:post_id>')
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route('/new-post', methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            author=form.author.data,
            body=form.body.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        flash('New blog post created successfully!', 'success')
        return redirect(url_for('get_all_posts'))

    return render_template("make-post.html", form=form)


@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login')) 
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        flash('Blog post edited successfully!', 'success')
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route('/delete/<int:post_id>')
@login_required
def delete_post(post_id):
    post = BlogPost.query.get(post_id)
    if not post:
        return redirect(url_for('unauthorized'))
    db.session.delete(post)
    db.session.commit()
    flash('Blog post deleted successfully!', 'success')
    return redirect(url_for('get_all_posts'))

@app.route('/unauthorized')
@login_manager.unauthorized_handler
def unauthorized():
    return render_template('error.html')

@app.route('/protected')
@login_required
def protected():
    return 'This is a protected route.'

@app.route("/about")
def about():
    return render_template("about.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/register", methods=['GET', 'POST'])
@login_required
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()
        if user:
            flash('Email already exists, please try Logging In instead.', 'danger')
            return redirect(url_for('login'))
        else:
            new_user = Users(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)
  

@app.route("/login-admin-amyth", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit(): 
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect, please try again.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Email does not exist, please try again.', 'danger')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    response = make_response(redirect(url_for('get_all_posts')))
    response.set_cookie('session', '', expires=0)
    logout_user()
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

from math import ceil

@app.route('/author/<author_name>')
def get_posts_by_author(author_name):
    page = request.args.get('page', default=1, type=int)
    per_page = 3 
    offset = (page - 1) * per_page
    with app.app_context():
        author_posts = BlogPost.query.filter_by(author=author_name)\
                                    .order_by(BlogPost.date.desc())\
                                    .offset(offset).limit(per_page).all()
        total_posts = len(BlogPost.query.filter_by(author=author_name).all())
        total_pages = ceil(total_posts / per_page)

    return render_template("index.html", all_posts=author_posts,
                           author_name=author_name, page=page,
                           total_pages=total_pages)


if __name__ == "__main__":
    app.run(debug=True)



