from calendar import monthrange
import flask_login
from flask import request, Blueprint, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required
from route.forms import User, RegistrationForm, LoginForm, OperationForm, Operation, Change
from config import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

fetch = Blueprint('fetch', __name__)


@fetch.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            message = 'Вы уже зарегистрированы'
            return render_template('register.html', form=form, message=message)
        hash = generate_password_hash(password)
        NewUser = User(
            email=email,
            password=hash,
            username=username
        )
        db.session.add(NewUser)
        db.session.commit()
        return redirect(url_for('fetch.login_post'))
    return render_template('register.html', form=form)


@fetch.route('/login', methods=['GET', 'POST'])
def login_post():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            message = 'Неверный пароль'
            return render_template('login.html', form=form, message=message)
        login_user(user, remember=remember)
        return redirect(url_for('fetch.profile'))
    return render_template('login.html', form=form)


@fetch.route('/operation', methods=['GET'])
def operation_post():
    form = OperationForm()
    if form.is_submitted():
        message = 'test'

    else:
        id = flask_login.current_user.id
        fromDate = request.args.get('fromDate')
        endDate = request.args.get('endDate')

        if not fromDate or not endDate:
            fromDate = datetime.today().replace(day=1).date()
            endDate = datetime.today().replace(day=31).date() or datetime.today().replace(
                day=30).date() or datetime.today().replace(day=28).date() or datetime.today().replace(day=29).date()
        else:
            fromDate = datetime.date(datetime.strptime(fromDate, '%Y-%m-%d'))
            endDate = datetime.date(datetime.strptime(endDate, '%Y-%m-%d'))
        res = list(map(lambda x: x.get_operation(), Operation.query.filter_by(userid=id).all()))
        result = 0

        for i in res:
            print(type(i[0]))
            if fromDate <= i[0] <= endDate:
                result += i[1]
        message = 'Сумма операций равна: ' + str(result)
        return render_template('operation.html', form=form, message=message)
    return render_template('operation.html', form=form, message=message)


@fetch.route('/operation/add', methods=['GET'])
def operation_add():
    form = OperationForm()
    return render_template('add-operation.html', form=form)


@fetch.route('/add-operation', methods=['POST'])
def add_operation():
    message = ''
    form = OperationForm()
    id = flask_login.current_user.id
    operation = form.operation.data
    date = form.date.data
    opersum = form.opersum.data
    print(operation)
    if operation in "Расход":
        opersum = opersum * (-1)
        print(opersum)

    res = Operation(
        userid=id,
        operation=operation,
        opersum=opersum,
        operdate=date
    )
    db.session.add(res)
    db.session.commit()
    message = 'Добавлено'

    return render_template('add-operation.html', form=form, message=message)


@fetch.route('/change-password', methods=['GET', 'POST'])
def change_password():
    message = ''
    form = Change()

    if form.is_submitted():
        password = form.password.data
        newPassword = form.newPassword.data
        hash = generate_password_hash(password)
        user = User.query.filter_by(id=flask_login.current_user.id, password=hash).all()

        print(user)
        if user:
            hash = generate_password_hash(newPassword)
            newPass = User.query.filter_by(id=flask_login.current_user.id)(
                password=hash
            )
            db.session.update(newPass)
            db.session.commit()
            message = 'пароль успешно изменен'
    return render_template('change-password.html', form=form, message=message)


@login_manager.user_loader
def load_user(user):
    return User.query.get(int(user))


@fetch.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@fetch.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('fetch.login_post'))
