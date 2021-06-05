from sqlalchemy import ForeignKey

from app import db
from flask_login import UserMixin
from sqlalchemy.sql import func

############################################################
### DATABASE ###############################################
############################################################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    department_code = db.Column(db.String(10))
    role_code = db.Column(db.String(10))
    #applications = db.relationship('Application', backref='user') #
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())

    def __init__(self, username, email, password, role_code, department_code):
        """object constractor"""
        self.username = username
        self.email = email
        self.password = password
        self.role_code = role_code
        self.department_code = department_code

    def __repr__(self):
        return '<User %r>' % self.username
        #return self.id

############################################################
class Valid_users(UserMixin, db.Model):
    """this class creates a new record into the db UserSystem and table valid_users"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    fname = db.Column(db.String(100))
    lname = db.Column(db.String(100))
    department_code = db.Column(db.String(10))
    role_code = db.Column(db.String(10))
    is_active = db.Column(db.String(1))
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())


    def __init__(self, username, fname, lname, department_code, role_code, is_active):
        """object constractor"""
        self.username = username
        self.fname = fname
        self.lname = lname
        self.department_code = department_code
        self.role_code = role_code
        self.is_active = is_active

    def __repr__(self):
        return '<User %r>' % self.username
        #return self.id


############################################################
class Document(UserMixin, db.Model):
    """this class extends to a web service authorized user"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    path = db.Column(db.String(100))
    name = db.Column(db.String(100))
    uname = db.Column(db.String(100))
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    application_id = db.Column(db.Integer, ForeignKey('application.id'))
    application = db.relationship('Application', back_populates="documents")

    def __init__(self, username, application, path, name, uname):
        """object constractor"""
        self.username = username
        self.application = application
        self.path = path
        self.name = name
        self.uname = uname

    def __repr__(self):
        return self.id

############################################################
class Application(UserMixin, db.Model):
    """this class creates a new record into the db UserSystem and table applications"""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    #user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    from_date = db.Column(db.String(30))
    to_date = db.Column(db.String(30))
    workpermit_type = db.Column(db.String(10))
    is_agreed = db.Column(db.String(1))
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    documents = db.relationship('Document', back_populates="application", uselist=True)

    def __init__(self, username, from_date, to_date, workpermit_type, is_agreed):
        """object constractor"""
        self.username = username
        self.from_date = from_date
        self.to_date = to_date
        self.workpermit_type = workpermit_type
        self.is_agreed = is_agreed

    def __repr__(self):
        return self.id

############################################################
class Workpermit(UserMixin, db.Model):
    """this class creates a new record into the db UserSystem and table workpermits"""
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), unique=True)
    description = db.Column(db.String(255))
    max_days = db.Column(db.Integer)
    is_enabled = db.Column(db.String(1))
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())

    def __init__(self, type, description, max_days, is_enabled):
        """object constractor"""
        self.type = type
        self.description = description
        self.max_days = max_days
        self.is_enabled = is_enabled

    def __repr__(self):
        return self.id

############################################################

############################################################
