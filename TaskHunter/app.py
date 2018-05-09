"""
before adding features, figure out how to structure the
project to scale better

first edit the file to keep the login system
but remove the bucketlist aspects of the application
    BREAKING GROUND:
-design the database schema
-design the views for the application
-add project to github
-create separate python anywhere account for the app
-learn/configure any apis used for the project
-test

note: in the future i plan to make this into a mobile app for android/iphone


list the new features here:
- allow users to create a group and add other registered memebers to them
    - add profile page for users
 """

from flask import Flask, render_template,redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField, TextField
from wtforms.validators import InputRequired,Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user









app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = 'mynewsecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///taskhunter.db'








db = SQLAlchemy(app)
login_manager = LoginManager() #manages user sessions
login_manager.init_app(app)#starts the process of flask login
login_manager.login_view = 'login'#route where user logs in
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(80))



#table for user profile, boolean if user has been invited?
#check if user has been invited every time?

#table for each group

#schema : [group name,role,member name,status(private or public),]

class Groups(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer(), primary_key=True)
    group_name = db.Column(db.String(80),unique=True)
    status = db.Column(db.Boolean, default=False) #true for private, false for public
    members = db.Column(db.String(100)) #list of current members

#table for the group members

class GroupMembers(db.Model):#find out how to change users status??
    __tablename__ = 'groupMembers'
    id = db.Column(db.Integer(), primary_key=True)
    group_name = db.Column(db.String(80),unique=True)
    member_name = db.Column(db.String(80), unique=True)
    member_role = db.Column(db.String(80))
    kicked = db.Column(db.Boolean, default=False) #checks to make sure member is authorized in the group
    #leader cant be kicked so should validate the user
    #any other info i should add to the table?





@login_manager.user_loader
def load_user(user_id):#connection between the datbase and flask-login
    return User.query.get(int(user_id)) #i dont know what this does

db.create_all()
db.session.commit()








class LoginForm(FlaskForm):
    username= StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password= PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])
    #remember me checkbox
    remember = BooleanField('remember me')



class RegisterForm(FlaskForm):
    email = StringField('email',validators=[InputRequired(), Email(message='Invalid email'),
    Length(max=50)])
    username= StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password= PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])

#form for inviting member??


@app.route('/')
def index():

    return render_template('index.html')


@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        #return '<h1> {} , {}</h1>'.format(form.username.data,form.password.data)
        #check to make sure password matches the users registered password
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                #redirect to the dashboard
                #first login the user
                login_user(user, remember=form.remember.data)
                return redirect(url_for("dashboard"))

        return "Invalid username or password"


    return render_template('login.html',form=form)






@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        #return "<h1> {}, {}</h1>".format(form.username.data,form.email.data)
        #put data into database
        #hash the password
        hashed_password = generate_password_hash(form.password.data, method='sha256')#must be 80 characters long
        new_user = User(username=form.username.data,
        email=form.email.data,password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect('/')



    return render_template('signup.html',form=form)

#will task hunter use the dashboard??
@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():

    logout_user()
    return redirect('/') #takes them to the homepage


#should profiles be public or private???
@app.route('/profile/<username>')#profile for users to accept invites
def profile():#backend for profile template
    #give the user option to create new groups
    #query the database for profile information
    #information should include recent invitees
    return render_template('profile.html')

#login required??
#could this be considered "loggin in" to the page

@app.route('/group/<groupname>')#create table for group chats
#page for the group
#check to see if group is public or private before allowing access
#should the leader of the group have the option of accessing an admin panel??

def group(groupname):
    #query the database for the group information
    #but which one though?
    #should eventually have the user chat, for now its just going to show a simple window with all members and
    #the functionality to add/delete users
    #should include functionality of being an admin as well
    #first query the

    data = Groups.query.filter_by(group_name=groupname).first_or_404()


    

    return render_template('group.html',data=data)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
