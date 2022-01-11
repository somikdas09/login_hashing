from enum import unique
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required,logout_user,current_user
from flask_wtf import FlaskForm
from flask_wtf import form
from flask_wtf.form import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms import validators
from wtforms.validators import InputRequired,Length,ValidationError
import hash

app=Flask(__name__)
db=SQLAlchemy(app)  #creates database instance

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'  #connects our app file tp database.db
app.config['SECRET_KEY']='thisisasecretkey'  #secret key is used to secure a session cookey

login_manager=LoginManager() # allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader  #user_loader call back will reload the user object from the user id stored in the session
def load_user(user_id):
    return User.query.get(int(user_id))

#table for our database
class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=False, unique=True)
    password=db.Column(db.String(80),nullable=False) #password has a max of 80 characters once its been hashed


#creating this registration form which will inherit from flask form
class RegisterForm(FlaskForm):
    username= StringField(validators=[InputRequired(),Length(
        min=4, max=20)],render_kw={"placeholder":"username"})
    password= PasswordField(validators=[InputRequired(),Length(
        min=4, max=20)],render_kw={"placeholder":"password"})
    submit=SubmitField("Register")    

    def validate_username(self,username):
        existing_user_username= User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("The username already exists. Please try different one")    


#creating this login form which will inherit from flask form
class LoginForm(FlaskForm):
    username= StringField(validators=[InputRequired(),Length(
        min=4, max=20)],render_kw={"placeholder":"username"})
    password= PasswordField(validators=[InputRequired(),Length(
        min=4, max=20)],render_kw={"placeholder":"password"})
    submit=SubmitField("Login") 
       
   


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()

    if form.validate_on_submit():
        user= User.query.filter_by(username=form.username.data).first()
        if user:
            if (hash.hash_compare(user.password,form.password.data)):
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/logout',methods=['GET','POST'])
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=hash.sha256(form.password.data)
        new_user=User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)






if __name__ =='__main__':
    app.run(debug=True)