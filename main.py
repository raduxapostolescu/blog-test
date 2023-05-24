from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from typing import List
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, Mapped, mapped_column, DeclarativeBase, Session
from sqlalchemy import ForeignKey, Integer
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(250), unique=True, nullable=False)
    subtitle    = db.Column(db.String(250), nullable=False)
    date        = db.Column(db.String(250), nullable=False)
    body        = db.Column(db.Text, nullable=False)
    img_url     = db.Column(db.String(250), nullable=False)

    author_id   = db.Column(db.Integer, db.ForeignKey("users.id"))
    author      = db.relationship("User", back_populates="posts")

    comments    = db.relationship("Comment", back_populates="parent_post")


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String(250), unique=True, nullable=False)
    password    = db.Column(db.String(250), nullable=False)

    posts       = db.relationship("BlogPost", back_populates="author")
    comments    = db.relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id              = db.Column(db.Integer, primary_key=True)
    text            = db.Column(db.Text, nullable=False)

    author_id       = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author  = db.relationship("User", back_populates="comments")

    post_id         = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    parent_post     = db.relationship("BlogPost", back_populates="comments")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.get_id() == "1":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"], method="pbkdf2:sha256", salt_length=8)

        with app.app_context():
            if User.query.filter_by(email=email).first():
                flash("User already exists. Please log in.")

                return redirect(url_for('register'))
            else:
                new_user = User(
                    email=email,
                    password=password
                )

                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate():
        login_email = request.form["email"]
        login_pass = request.form["password"]

        with app.app_context():
            db_user = User.query.filter_by(email=login_email).first()

            if db_user and check_password_hash(db_user.password, login_pass):
                login_user(db_user, remember=True)

                return redirect(url_for('get_all_posts'))

            elif db_user and not check_password_hash(db_user.password, login_pass):
                flash("Credentials are incorrect. Please try again.")

                return redirect(url_for('login'))

            elif not db_user:
                flash("No account under that email found. Please register!")

                return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    comments = Comment.query.all()

    if request.method == "POST":
        comment = request.form["comment"]

        with app.app_context():
            new_comment = Comment(
                text=comment,
                comment_author=current_user
            )
            db.session.add(new_comment)
            db.session.commit()

    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
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
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
