from functools import wraps

import flask_login
from flask import url_for, redirect, Flask, render_template, request, g
from flask_login import LoginManager, login_required, login_user, UserMixin, ID_ATTRIBUTE, current_user
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask import abort
from flask_ckeditor import CKEditor, CKEditorField

ckeditor = CKEditor()
login_manager = LoginManager()
app = Flask(__name__)

login_manager.init_app(app)

app.config['SECRET_KEY'] = 'C2HWGVoMGfNTBsrYQg8EcMrdTimkZfAb'
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

ckeditor.init_app(app=app)


class PostForm(FlaskForm):
    author = StringField("author name", validators=[DataRequired()])
    date = StringField("date", validators=[DataRequired()])
    post = StringField("entry", validators=[DataRequired()])
    title = StringField("title", validators=[DataRequired()])
    submit = SubmitField("submit")


class CreateUser(FlaskForm):
    user = StringField("name", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired()])
    password = StringField("password", validators=[DataRequired()])
    submit = SubmitField("submit")


class LoginForm(FlaskForm):
    user = StringField("name", validators=[DataRequired()])
    password = StringField("password", validators=[DataRequired()])
    submit = SubmitField("submit")


class CommentForm(FlaskForm):
    body = CKEditorField("body")


    sumbit = SubmitField("submit")


class Posts(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String, db.ForeignKey("users.user"))
    date = db.Column(db.String, unique=False, nullable=False)
    post = db.Column(db.String, unique=True, nullable=False)
    title = db.Column(db.String, unique=True, nullable=False)


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String, unique=True)


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comments = db.Column(db.String, unique=False)
    author = db.Column(db.String, db.ForeignKey("users.user"))
    attached_post = db.Column(db.String, db.ForeignKey("posts.title"))


app.app_context().push()
db.create_all()


@login_manager.user_loader
def user_loader(ident):
    return db.session.get(Users, ident=ident)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def home():
    posts = db.session.query(Posts).all()
    return render_template("home.html", posts=posts)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        user = db.session.query(Users).filter_by(user=form.user.data).first()

        user = db.session.get(Users, ident=user.id)
        login_user(user=user)
        return redirect("/")

    return render_template("login.html", form=form)


@app.route("/make_post", methods=["GET", "POST"])
@admin_only
def make_post():
    form = PostForm()

    if request.method == "POST":
        posts = Posts(
            author=form.author.data,
            date=form.date.data,
            post=form.post.data,
            title=form.title.data
        )
        db.session.add(posts)
        db.session.commit()

        return redirect("/")
    return render_template("make_post.html", form=form)


@app.route("/create_user", methods=["GET", "POST"])
def create_user():
    form = CreateUser()
    if request.method == "POST":
        password = generate_password_hash(form.password.data, salt_length=8)
        user = Users(
            user=form.user.data,
            email=form.email.data,
            password=password
        )
        db.session.add(user)
        db.session.commit()
        return redirect("/")

    return render_template("create_user.html", form=form)


@app.route("/edit", methods=["GET", "POST"])
@admin_only
def edit_post():
    info = db.session.query(Users).all()
    print(info)
    return render_template("edit_pages.html")


def add_comments(post):
    comment = Comments(
        comments=post[0],
        author=post[1]
    )
    db.session.add(comment)


@app.route("/viewpost/<int:id>")
def view_post(id):
    comment_form = CommentForm()
    post = db.session.get(Posts, id)
    comments = db.session.query(Comments).filter_by(attached_post=post.title).all()
    return render_template("view_post.html", form=post, comments=comments,comment_form=comment_form )


if __name__ == '__main__':
    app.run(debug=True)
