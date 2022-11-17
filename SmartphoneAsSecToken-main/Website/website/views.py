from flask import Blueprint, render_template, session, flash, redirect
from .models import User
from . import db

views = Blueprint('views', __name__)

@views.route('/home_user' , methods = ['GET', 'POST'])
def home_user():
    if 'authenticated' not in session or 'credentials' not in session:
            flash('User is not authenticated', category='error')
            session.pop('credentials', None)
            session.pop('authenticated', None)
            return redirect('/')

    user = User.query.filter_by(id=session['credentials']).first()

    return render_template("home_user.html", username=user.username, money = user.money)


