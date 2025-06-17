from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp # Import Regexp for phone number validation
from flask_wtf.file import FileField, FileAllowed
# Assuming User model is defined in models.py and accessible
# from models import User # You might need this if you have custom validators that query the User model

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15), # Adjust min/max length as needed for phone numbers
        Regexp(r'^\+?1?\d{9,15}$', message="Invalid phone number format.") # Basic regex for phone numbers
    ]) # <--- ADD THIS LINE
    submit = SubmitField('Sign Up')

    # Add custom validators if needed, e.g., to check for unique username/email
    # def validate_username(self, username):
    #     user = User.query.filter_by(username=username.data).first()
    #     if user:
    #         raise ValidationError('That username is taken. Please choose a different one.')

    # def validate_email(self, email):
    #     user = User.query.filter_by(email=email.data).first()
    #     if user:
    #         raise ValidationError('That email is taken. Please choose a different one.')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()]) # Use StringField then convert to float in route
    stock = StringField('Stock', validators=[DataRequired()]) # Use StringField then convert to int in route
    category = StringField('Category', validators=[DataRequired(), Length(max=50)])
    picture = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Add Product')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update')

    # def validate_username(self, username):
    #     if username.data != current_user.username:
    #         user = User.query.filter_by(username=username.data).first()
    #         if user:
    #             raise ValidationError('That username is taken. Please choose a different one.')

    # def validate_email(self, email):
    #     if email.data != current_user.email:
    #         user = User.query.filter_by(email=email.data).first()
    #         if user:
    #             raise ValidationError('That email is taken. Please choose a different one.')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    # def validate_email(self, email):
    #     user = User.query.filter_by(email=email.data).first()
    #     if user is None:
    #         raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AdminProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()]) # Use StringField then convert to float in route
    stock = StringField('Stock', validators=[DataRequired()]) # Use StringField then convert to int in route
    category = StringField('Category', validators=[DataRequired(), Length(max=50)])
    picture = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Save Product')

class AdminUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = StringField('Role', validators=[DataRequired()]) # e.g., 'customer', 'admin', 'sales_representative'
    submit = SubmitField('Save User')

class AdminOrderForm(FlaskForm):
    status = StringField('Order Status', validators=[DataRequired()]) # e.g., 'Pending', 'Shipped', 'Delivered'
    address = TextAreaField('Shipping Address', validators=[DataRequired()])
    submit = SubmitField('Update Order')