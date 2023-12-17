from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField, SelectField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Optional
from config import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(1000))

    def get_name(self):
        return self.username

    def get_email(self):
        return self.username


class Operation(UserMixin, db.Model):
    __tablename__ = 'operation'
    id = db.Column(db.Integer, primary_key=True)
    operdate = db.Column(db.Date)
    userid = db.Column(db.Integer)
    operation = db.Column(db.String(1000))
    opersum = db.Column(db.Integer)

    def get_operation(self):
        return self.operdate, self.opersum


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class OperationForm(FlaskForm):
    date = DateField('From Date', validators=[DataRequired()])
    operation = SelectField('Operation sum', choices=[('Доход', 'доход'), ('Расход', 'расход')],
                            validators=[DataRequired()])
    opersum = FloatField('Date', validators=[DataRequired()])
    fromDate = DateField('From Date', validators=[Optional()])
    endDate = DateField('End Date', validators=[Optional()])
    submit = SubmitField('Get operation')


class Change(FlaskForm):
    password = PasswordField('Старый пароль', validators=[DataRequired()])
    newPassword = PasswordField('Новый пароль', validators=[DataRequired()])
    newPassword2 = PasswordField(
        'Повторите новый пароль', validators=[DataRequired(), EqualTo('newPassword')])
    submit = SubmitField('Изменить')
