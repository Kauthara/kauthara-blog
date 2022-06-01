import os

from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Integer, String, Text, Column, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask_gravatar import Gravatar

import forms
from forms import CreatePostForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '8BYkEfBA6O6donzWlSihBXox7C0sKR6b')
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
# When running online
engine = create_engine(os.environ.get('DATABASE_URL1', 'sqlite:///blog.db'), echo=False)
# When running locally
# engine = create_engine(os.environ.get('DATABASE_URL1', 'sqlite:///blog.db'), echo=False, connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return session.query(User).get(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# CONFIGURE TABLES
class User(Base, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    blogposts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="author")

    def __repr__(self):
        return f"email: {self.email}, name: {self.name}"


class BlogPost(Base):
    __tablename__ = "blog_posts"

    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="blogposts")
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

    def __repr__(self):
        return f"title: {self.title}, subtitle: {self.subtitle}, date: {self.date}, " \
               f"body: {self.body}, img_url: {self.img_url}"


class Comment(Base):
    __tablename__ = 'comments'

    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = Column(Text, nullable=False)

    def __repr__(self):
        return f"id: {self.id}, text: {self.text}"


@app.route('/')
def get_all_posts():
    posts = session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, admin=request.args.get('admin'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
        name = form.name.data
        check_email = session.query(User).filter(User.email == email).one_or_none()
        if check_email is None:
            new_user = User(email=email, password=password, name=name)
            session.add(new_user)
            session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("You've already signed up with that email. Log in instead")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = session.query(User).filter(User.email == email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                if user.id == 1:
                    admin = True
                else:
                    admin = False
                return redirect(url_for('get_all_posts', admin=admin))
            else:
                flash('Invalid password')
                return redirect(url_for('login'))
        else:
            flash('This email does not exist')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = forms.CommentForm()
    requested_post = session.query(BlogPost).filter(BlogPost.id == post_id).first()
    admin = None
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True
    else:
        admin = False
    # if form.validate_on_submit():
    #     if current_user.is_authenticated:
    #         comment = form.comment.data
    #         new_comment = Comment(text=comment, author=current_user, parent_post=requested_post)
    #         session.add(new_comment)
    #         session.commit()
    #         # return redirect(url_for('get_all_posts', admin=admin))
    #     else:
    #         flash("Please Login before commenting")
    #         return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, admin=admin, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        session.add(new_post)
        session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = session.query(BlogPost).filter(BlogPost.id == post_id).first()
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    session.delete(post_to_delete)
    session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    app.run(host='0.0.0.0', port=5000, debug=True)

