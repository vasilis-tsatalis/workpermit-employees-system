from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, IntegerField  # boolean field is for checkbox
from wtforms.validators import InputRequired, Email, Length, EqualTo, Regexp


class LoginForm(FlaskForm):
    """create a new form object for each login with these elements below"""
    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')


############################################################
class RegisterForm(FlaskForm):
    """create a new form object for each registration with these elements below"""
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=10, max=100)])
    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=20)])
    password = PasswordField('Password',
                             validators=[InputRequired(), EqualTo(fieldname='password2'), Length(min=8, max=80)])
    password2 = PasswordField('Confirm Password', validators=[InputRequired(), Length(min=8, max=80)])


############################################################
class ValidationForm(FlaskForm):
    """create a new form object for each valid_user with these elements below"""
    departments = ('ICT', 'RISK', 'MARKETING', 'SALES', 'FINANCE', 'HR')
    roles = ('USER', 'ADMIN')

    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=20)])
    fname = StringField('First Name', validators=[InputRequired(), Length(min=5, max=100)])
    lname = StringField('Last Name', validators=[InputRequired(), Length(min=5, max=100)])
    role_code = SelectField('Role Code', choices=roles)
    department_code = SelectField('Department Code', choices=departments)
    is_active = SelectField('Active Account', choices=['Y', 'N'])


############################################################
class ViewerForm(FlaskForm):
    """create a new form object for each valid_user with these elements below"""
    id = IntegerField('PDF Document ID', validators=[InputRequired()])


############################################################
class SearchForm(FlaskForm):
    """create a new form object for each input via searching bar"""
    username = StringField('Username', validators=[InputRequired(), Length(min=5, max=20)])


############################################################
class UploadForm(FlaskForm):
    """create a new form object for each input via searching bar"""
    id = IntegerField('Application ID', validators=[InputRequired()])


############################################################
class CreateApplicationForm(FlaskForm):
    """create a new form object for each application with these elements below"""
    workpermit_types = ('GENERIC', 'EXAMS', 'MOTHER')

    from_date = StringField('Start Date YYYY-MM-DD', validators=[InputRequired(), Regexp('\d{4}-\d{2}-\d{2}', message='It must be in the form of XXXX-XX-XX')])
    to_date = StringField('End Date YYYY-MM-DD', validators=[InputRequired(), Regexp('\d{4}-\d{2}-\d{2}', message='It must be in the form of XXXX-XX-XX')])
    workpermit_type = SelectField('Workpermit Type', choices=workpermit_types)


class ApproveApplicationForm(CreateApplicationForm):
    is_agreed = SelectField('Accepted', choices=['Y', 'N'])

############################################################
class WorkpermitForm(FlaskForm):
    """create a new form object for table insert workpermit types"""
    type = StringField('Workpermit Type', validators=[InputRequired(), Length(min=2, max=10)])
    description = StringField('Description')
    max_days = StringField('Number of Days', validators=[InputRequired()])
    is_enabled = SelectField('Enabled', choices=['Y', 'N'])


############################################################