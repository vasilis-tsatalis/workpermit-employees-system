from flask import Flask, request, Response, render_template, redirect, url_for, flash, send_from_directory
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message

import os
import calendar
import time
from datetime import date
from dotenv import load_dotenv
import smtplib

############################################################
### IMPORT MY FUNCTIONS ####################################
from forms import *

load_dotenv(verbose=True)

current_date = str(date.today())
# current_time = str(time.time()) # float
current_time = str(calendar.timegm(time.gmtime()))  # int
timestamp = current_date + '_' + current_time

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# Dependency
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy()
db.init_app(app)

from models import *

app.config['STORAGE_FOLDER'] = '.' + os.path.sep + 'uploaded'
# if folder for documents does not exist create it
if not os.path.isdir(app.config['STORAGE_FOLDER']):
    os.mkdir(app.config['STORAGE_FOLDER'])
ALLOWED_EXTENSIONS = {'pdf', 'PDF'} 

bootstrap = Bootstrap(app)


# SMTP Process
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = os.getenv("MAIL_PORT")
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
app.config['MAIL_USE_SSL'] = os.getenv("MAIL_USE_SSL") == "True"

mail = Mail(app) 


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

############################################################
############################################################
### ENDPOINTS SITE #########################################
############################################################
@login_manager.user_loader
def load_user(username):
    """this will create a connection between flask login and the requested database id"""
    return User.query.get(username)

############################################################
@app.route('/')
def index():
    admin_user = os.getenv("ADMIN_USERNAME")
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_pass = os.getenv("ADMIN_PASS")
    db.create_all()
    db.session.commit()
    # create the admin user if not exists
    user = User.query.filter_by(username=admin_user.upper()).first()
    if user is None:
        hashed_password = generate_password_hash(admin_pass, method='sha256')
        new_user = User(username=admin_user.upper(), email=admin_email.lower(), password=hashed_password, role_code='ADMIN', department_code='HR')
        db.session.add(new_user)# this inserts into the table the new record
        db.session.commit()# this will verify the insert command
    return render_template('index.html')

############################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    """pass the object class LoginForm into the function"""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.upper()).first_or_404()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                # control user role admin-user
                #email_sender(current_user.email)
                if current_user.role_code != 'ADMIN':
                    return redirect(url_for('user_dash'))
                else:
                    return redirect(url_for('dashboard'))
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)

############################################################
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """pass the object class RegisterForm into the function"""
    form = RegisterForm()
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        check_user = User.query.filter_by(username=form.username.data.upper()).first()
        if check_user:
            return '<h1>Cannot register this user, already exists</h1>'
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # find all existing user from the table
        exist_user = Valid_users.query.filter_by(username=form.username.data.upper()).first()
        if exist_user is None or exist_user.is_active != 'Y':
            return '<h1>Cannot create a user to use the app</h1>'
        new_user = User(username=form.username.data.upper(), email=form.email.data.lower(), password=hashed_password, department_code=exist_user.department_code, role_code=exist_user.role_code)
        db.session.add(new_user)# this inserts into the table the new record
        db.session.commit()# this will verify the insert command
        text = """
                Hi, you have been created a new account, please login!!!
                """
        receivers = form.email.data.lower()
        email_sender(receivers, text)
        return redirect(url_for('login'))
        # return '<h1> New User ' + register_form.username.data +  ' has been created with role ' + user_role + '</h1>'
    return render_template('signup.html', form=form)

############################################################
@app.route('/dashboard', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def dashboard():
    return render_template('dashboard.html',
                           name=current_user.username, role=current_user.role_code)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/mydash', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def user_dash():
    return render_template('user_dash.html',
                           name=current_user.username, role=current_user.role_code)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/users', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def read_users():
    users = User.query.all()  # return a list with all values
    return render_template('users.html', name=current_user.username, role=current_user.role_code,
                           users=users)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/user', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def create_user():
    form = ValidationForm() 
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        new_user = Valid_users(username=form.username.data.upper(), fname=form.fname.data, lname=form.lname.data, department_code=form.department_code.data, is_active=form.is_active.data, role_code=form.role_code.data)
        db.session.add(new_user)  # this inserts into the table the new record
        db.session.commit()  # this will verify the insert command
        return redirect(url_for('create_user'))  
    return render_template('create_user.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/find_user', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def find_user_by_username():
    form = SearchForm() 
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        search_user = User.query.filter_by(username=form.username.data.upper()).first()
        if search_user:
             return render_template('find_user.html', name=current_user.username, role=current_user.role_code, search_user=search_user, form=form)
        else:
            return redirect(url_for('find_user_by_username'))
    return render_template('find_user.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/edit_user', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def edit_user_by_username():
    form = SearchForm()
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        search_user = Valid_users.query.filter_by(username=form.username.data.upper()).first()
        if search_user:
            query = ValidationForm(username=search_user.username, fname=search_user.fname, lname=search_user.lname,
                                   role_code=search_user.role_code, department_code=search_user.department_code,
                                   is_active=search_user.is_active)
            return render_template('edit_user.html', name=current_user.username, role=current_user.role_code, form=query, search_user=search_user)
        else:
            return redirect(url_for('edit_user_by_username'))
    return render_template('edit_user.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/edit_user_info', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def edit_user_info():
    form = ValidationForm()

    if request.method == 'POST':
        user_to_edit = Valid_users.query.filter_by(username=form.username.data.upper()).first()
        user_to_edit.fname = form.fname.data
        user_to_edit.lname = form.lname.data
        user_to_edit.role_code = form.role_code.data
        user_to_edit.department_code = form.department_code.data
        user_to_edit.is_active = form.is_active.data
        db.session.commit()
        flash("User " + form.username.data + " updated.")
        return redirect(request.url)
    return render_template('edit_user.html', name=current_user.username, role=current_user.role_code, form=form)

############################################################
@app.route('/delete_user/<int:id>')
@login_required  # cannot access the dashboard before you login first
def delete_user(id):
    user_to_delete: User = User.query.get_or_404(id)
    valid_user_to_delete = Valid_users.query.filter_by(username=user_to_delete.username).first()
    try:
        db.session.delete(user_to_delete)
        db.session.delete(valid_user_to_delete)
        db.session.commit()
        return redirect("/users")
    except Exception:
        return "There was a problem deleting this user."

############################################################
@app.route('/admin_info', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def find_admin_data():
    return render_template('admin_data.html', user=current_user)
############################################################
@app.route('/user_info', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def find_user_data():
    return render_template('user_data.html', user=current_user)

############################################################
@app.route('/valid_users', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def valid_users():
    """this function adda new valid_user and the user can be register"""
    vusers = Valid_users.query.all()  # return a list with all values
    return render_template('valid_users.html', name=current_user.username, role=current_user.role_code, vusers=vusers)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/documents', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def documents():
    """this function displays all the uploaded pdf documents"""
    documents = Document.query.all()  # return a list with all values
    return render_template('documents.html', name=current_user.username, role=current_user.role_code, 
                           documents=documents)  # name parameter send to html the value of the current logged_in user
############################################################
@app.route('/app_documents/<int:id>', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def app_documents(id):
    """this function displays all the uploaded pdf documents"""
    documents = Document.query.filter_by(application_id=id)  # return a list with all values
    return render_template('app_documents.html', name=current_user.username, role=current_user.role_code,
                           documents=documents)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/viewer', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def viewer():
    form = ViewerForm()
    if request.method == 'POST':
        pdf_id = int(form.id.data)
        pdf_data = Document.query.filter_by(id=pdf_id).first()
        if pdf_data is not None:
            return send_from_directory(pdf_data.path, pdf_data.name)
        else:
            return redirect(url_for('documents'))
    else:
        return render_template('viewer.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/upload', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def upload_file():
    """this function uploads a documents for an application"""
    # the control below will be true with on click to submit button
    form = UploadForm()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            stored_name = timestamp + '_' + str(form.id.data) + '.pdf'
            file.save(os.path.join(app.config['STORAGE_FOLDER'], stored_name))
            flash('File ' + filename + ' successfully uploaded')

            application_to_add_doc: Application = Application.query.get_or_404(form.id.data)
            new_doc = Document(username = current_user.username, uname=filename, path=app.config['STORAGE_FOLDER'], name=stored_name, application=application_to_add_doc)

            application_to_add_doc.documents.append(new_doc)
            db.session.add(application_to_add_doc)  # this inserts into the table the new record
            db.session.commit()  # this will verify the insert command
            return redirect(request.url)
        else:
            flash('Allowed file type is "pdf"')
            return redirect(request.url)

    return render_template('upload.html',
                           name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/user_docs', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def find_documents_by_username():
    """this function displays all the uploaded pdf documents"""
    documents = Document.query.filter_by(username=current_user.username)  # return a list with all values
    if documents is None:
        return redirect(url_for('find_documents_by_username'))
    return render_template('user_docs.html', name=current_user.username, role=current_user.role_code, 
                           documents=documents)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/user_upload', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def upload_user_doc():
    """this function uploads a documents for an application"""
    # the control below will be true with on click to submit button
    form = UploadForm()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            stored_name = timestamp + '_' + str(form.id.data) + '.pdf'
            file.save(os.path.join(app.config['STORAGE_FOLDER'], stored_name))
            flash('File ' + filename + ' successfully uploaded')

            application_to_add_doc: Application = Application.query.get_or_404(form.id.data)
            new_doc = Document(username = current_user.username, uname=filename, path=app.config['STORAGE_FOLDER'], name=stored_name, application=application_to_add_doc)

            application_to_add_doc.documents.append(new_doc)
            db.session.add(application_to_add_doc)  # this inserts into the table the new record
            db.session.commit()  # this will verify the insert command
            return redirect(request.url)
        else:
            flash('Allowed file type is "pdf"')
            return redirect(request.url)

    return render_template('user_upload.html',
                           name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/user_printer', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def user_pdf_viewer():
    form = ViewerForm()
    if request.method == 'POST':
        pdf_id = int(form.id.data)
        pdf_data = Document.query.filter_by(id=pdf_id).first()
        if pdf_data is not None:
            return send_from_directory(pdf_data.path, pdf_data.name)
        else:
            return redirect(url_for('user_pdf_viewer'))
    else:
        return render_template('user_printer.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/applications', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def read_applications():
    applications = Application.query.all()  # return a list with all values
    return render_template('applications.html', name=current_user.username, role=current_user.role_code,
                           applications=applications)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/application', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def create_application():
    form = CreateApplicationForm()
    # the control below will be true with on click to submit button
    if request.method == 'POST':
        if form.validate_on_submit():
            new_application = Application(username=current_user.username, from_date=form.from_date.data, to_date=form.to_date.data, workpermit_type=form.workpermit_type.data, is_agreed='P')
            db.session.add(new_application)  # this inserts into the table the new record
            db.session.commit()  # this will verify the insert command
            return redirect(url_for('create_application'))
        else:
            flash('Error on input data.')
            render_template('create_application.html', name=current_user.username, role=current_user.role_code, form=form)
    else:
        # adding custom workpermits to form list
        form.workpermit_type.choices.extend(list(map(lambda x: x.type, Workpermit.query.all())))

        # name parameter send to html the value of the current logged_in user
        return render_template('create_application.html', name=current_user.username, role=current_user.role_code, form=form)

############################################################
@app.route('/find_app', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def find_applications_by_username():
    form = SearchForm() 
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        search_apps = Application.query.filter_by(username=form.username.data.upper())
        if search_apps:
            render_template('find_application.html', name=current_user.username, role=current_user.role_code, search_apps=search_apps, form=form)
        else:
            return redirect(url_for('find_applications_by_username'))
    return render_template('find_application.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/user_apps', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def find_user_applications():
    # the control below will be true with on click to submit button
    applications = Application.query.filter_by(username=current_user.username)
    if applications is None:
        return redirect(url_for('find_user_applications'))
    return render_template('user_apps.html', name=current_user.username, role=current_user.role_code, applications=applications)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/new_app', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def create_user_application():
    form = CreateApplicationForm()
    # the control below will be true with on click to submit button
    if request.method == 'POST':
        new_application = Application(username=current_user.username, from_date=form.from_date.data, to_date=form.to_date.data, workpermit_type=form.workpermit_type.data, is_agreed='P')
        db.session.add(new_application)  # this inserts into the table the new record
        db.session.commit()  # this will verify the insert command
        return redirect(url_for('create_user_application'))  
    return render_template('user_new_app.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/workpermits', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def read_workpermits():
    workpermits = Workpermit.query.all()  # return a list with all values
    return render_template('workpermits.html', name=current_user.username, role=current_user.role_code,
                           workpermits=workpermits)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/workpermit', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def create_workpermit():
    form = WorkpermitForm() 
    # the control below will be true with on click to submit button
    if form.validate_on_submit():
        new_workpermit = Workpermit(type=form.type.data.upper(), description=form.description.data, max_days=form.max_days.data, is_enabled=form.is_enabled.data)
        db.session.add(new_workpermit)  # this inserts into the table the new record
        db.session.commit()  # this will verify the insert command
        return redirect(url_for('create_workpermit'))
    return render_template('create_workpermit.html', name=current_user.username, role=current_user.role_code, form=form)  # name parameter send to html the value of the current logged_in user
############################################################
@app.route('/edit_workpermit/<int:id>', methods=['GET', 'POST'])
@login_required  # cannot access the dashboard before you login first
def edit_workpermit(id):
    form = WorkpermitForm()

    workpermit_to_edit: Workpermit = Workpermit.query.get_or_404(id)

    if request.method == 'POST':
        if form.validate_on_submit():
            workpermit_to_edit.type = request.form['type'].upper()
            workpermit_to_edit.description = request.form['description']
            workpermit_to_edit.max_days = request.form['max_days']
            workpermit_to_edit.is_enabled = request.form['is_enabled']
            db.session.commit()
            return redirect(url_for('read_workpermits'))
        else:
            flash('Invalid input data for work permit.')
            return render_template('edit_workpermit.html', name=current_user.username, role=current_user.role_code,
                                   form=form, wp_id=id)
    else:
        form = WorkpermitForm(type=workpermit_to_edit.type, description=workpermit_to_edit.description,
                              max_days=workpermit_to_edit.max_days, is_enabled=workpermit_to_edit.is_enabled)
        return render_template('edit_workpermit.html', name=current_user.username, role=current_user.role_code,
                               form=form, wp_id=id)


############################################################
@app.route('/delete_workpermit/<int:id>', methods=['GET'])
@login_required  # cannot access the dashboard before you login first
def delete_workpermit(id):
    workpermit_to_delete = Workpermit.query.get_or_404(id)

    try:
        db.session.delete(workpermit_to_delete)
        db.session.commit()
        return redirect(url_for('read_workpermits'))
    except Exception:
        return 'There was a problem when deleting workpermit'

############################################################
@app.route('/about')
@login_required  # cannot access the dashboard before you login first
def about():
    return render_template('about.html',
                           name=current_user.username, role=current_user.role_code)  # name parameter send to html the value of the current logged_in user

############################################################
@app.route('/logout')
@login_required # cannot logout before you login first
def logout():
    logout_user()
    db.session.close()
    return redirect(url_for('index')) # if the user choose to logout redirect to the index page

############################################################


############################################################
############################################################
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def email_sender(receivers, message):

    sender = os.getenv("ADMIN_EMAIL")
    msg = Message("Welcome!",
        sender = sender,
        recipients=[receivers])
    msg.body = message
    try:
        mail.send(msg)
    except BadHeaderError:
        print(BadHeaderError)
        return "Bad Header Error"


############################################################

""" Run the application """
HOST = os.getenv("HOST")
PORT = os.getenv("PORT")

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=True, threaded=True)
