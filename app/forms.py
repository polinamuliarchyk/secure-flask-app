from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, EmailField, SelectField
from wtforms.validators import DataRequired, Length, Email, Optional, EqualTo, Regexp


class AddUserForm(FlaskForm):
    new_username = StringField("Username", validators=[
        DataRequired(),
        Length(min=3, max=50),
        Regexp("^[A-Za-z0-9_.-]+$")
    ])

    new_name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    new_lastname = StringField('Lastname', validators=[DataRequired(), Length(max=50)])
    new_password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    new_email = EmailField('Email', validators=[DataRequired(), Email()])
    new_role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('admin', 'Admin')],
                           default='student')
    submit = SubmitField('Add User')


class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    name = StringField('Name', validators=[Optional(), Length(max=50)])
    lastname = StringField('Lastname', validators=[Optional(), Length(max=50)])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    email = EmailField('Email', validators=[Optional(), Email()])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('admin', 'Admin')])
    submit = SubmitField('Update User')


class DeleteUserForm(FlaskForm):
    pass


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')


class EmailCodeForm(FlaskForm):
    token = StringField('Confirmation code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Confirm')


class QRVerifyForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=64)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password"),
            EqualTo("password", message="Passwords must match")
        ]
    )
    submit = SubmitField('Create account')


class MFAChoiceForm(FlaskForm):
    mfa_method = RadioField('Select confirmation method',
                            choices=[('totp', 'Authenticator App'), ('email', 'Email')],
                            validators=[DataRequired()])
    submit = SubmitField('Continue')

