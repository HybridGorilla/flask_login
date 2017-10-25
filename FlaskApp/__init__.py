import binascii
import urllib
import time
import hashlib
from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from flask import render_template
from flask import jsonify
from flask import abort
import flask_bouncer as bouncer
from bouncer import authorization_method
from flask_bouncer import requires
from flask_bouncer import Bouncer
import flask_login

app = Flask(__name__)
app.config.from_pyfile('instance/config.py')
app.config['SECRET_KEY'] = "b253d70da319d666a220aecec77f6d87cda2e655837c571c229ed59fc1a0a7eb"

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


import FlaskApp.database
import FlaskApp.models
from FlaskApp.models import db
from FlaskApp.models import Users


users_table = Users
db.init_app(app)
t = time.time()


def gen_token():
    randCode = binascii.hexlify(os.urandom(24))
    return randCode


@authorization_method
def authorize(user, they):
    print "Bombed out here..."
    if user.is_admin:
        they.can(READ, ALL)
    else:
        they.can(READ, 'Normal')


@login_manager.user_loader
def user_loader(userName):
    if users_table.query.get(userName) is not None:
        return users_table.query.get(userName)
    else:
        return None


@login_manager.request_loader
def request_loader(request):
    token = request.headers.get('username')
    passWord = request.headers.get('password')
    if token is None:
        return None

    if token is not None:
        user_entry = users_table.get(u_name)
        if (user_entry is not None):
            user = users_table(user_entry[0],user_entry[1])
            if (user.p_word == passWord):
                user.is_authenticated()
                return user
    return None


@login_manager.unauthorized_handler
def unauthorized_hander():
    return render_template("unauthorised.html")


def makeDict(my_dict):
    object_list = []
    for u in my_dict:
        ret_dict = dict(u.__dict__)
        ret_dict.pop('_sa_instance_state')
        object_list.append(ret_dict)
    return object_list


def auth_check():
    user = flask_login.current_user.u_name
    permission = users_table.query.filter_by(u_name=user).first()

    if permission.role != "admin":
        return False
    else:
        return True


@app.route("/get_users")
@flask_login.login_required
def dbtest():
    if auth_check() == False:
        abort(401)
    data = makeDict(users_table.query.all())
    return render_template("userlist.html", objects=data)


@app.route("/")
def hello():
    return render_template('index.html')


@app.route('/protected')
@flask_login.login_required
def protected():
    return render_template('protected.html')


@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return render_template('logout.html')


@app.route("/login", methods=['GET','POST'])
def login():
    from flask import request
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userName = request.form['username']
        passWord = request.form['password']
        print (userName)
        print (passWord)
        check = users_table.query.all()
        for x in check:
            salty = hash_pass(x.pj_salt, passWord)
            if x.u_name == userName and x.p_word == salty:
                user = x
                flask_login.login_user(user)
                return redirect(url_for('protected'))

        return "Login Failed!"


@app.route("/info")
@flask_login.login_required
def info():
    return render_template('info.html')


@app.route("/routes")
def routes():
    dict = {}
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, rule))
        output.append(line)

    for x in output:
        return render_template('routes.html', routes=output)


@app.route("/admin_mod", methods=['GET','POST'])
@flask_login.login_required
def admin_mod():
    if auth_check() == False:
        abort(403)
    if request.method == 'POST':
        username = request.form['username2']
        password = request.form['password2']
        bio = request.form['bio']

        get_user = users_table.query.filter_by(u_name=username).first()
        test = ["objects", "go", "in", "lists"]
        salt = gen_salt(get_user.u_name).hexdigest()
        password = hash_pass(salt, password)
        db_push = users_table.query.filter_by(u_name=username).update(dict(p_word=password, pj_salt=salt, bio=bio))
        db.session.commit()
        object_list = [ "Update Successful!" ]

        return render_template("admin.html", flashbox=object_list)

    return redirect(url_for('admin'))


@app.route("/admin", methods=['GET','POST'])
@flask_login.login_required
def admin():
    if auth_check == False:
        abort(403)

    objects = []

    if request.method == "POST":
        username = request.form['username']
        search = users_table.query.filter_by(u_name=username).first()
        x = search.u_name
        y = search.pj_salt
        z = search.p_word
        v = search.bio
        things = ["objects", "go", "in", "lists"]
        object_list = [
                        x,
                        y,
                        z,
                        v
                      ]
        # Note: weird behaviour (or I'm tired), the 2nd set of objects isn't loading
        # until after the 'object_list' is loaded by performing a search, its like a
        # global AJAX request is made internally when a search is performed (vOv)
        return render_template("admin.html", output=object_list, modalblob=things)

    return render_template("admin.html")


@app.errorhandler(500)
def server_error(error):
    return render_template("server_error.html")


@app.errorhandler(401)
def not_permitted(error):
    return render_template("401.html")


@app.errorhandler(403)
def forbidden(error):
    return render_template("forbidden.html")


@app.errorhandler(404)
def not_found(error):
    return render_template("not_found.html")


def gen_salt(username):
    salt = hashlib.md5(username)
    return salt

def hash_pass(salt,password):
    full_hash = hashlib.sha256(password + salt)
    return full_hash.hexdigest()


@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    role = ""
    username = request.form['username']
    password = request.form['password']
    salt = gen_salt(username).hexdigest()

    if username == "admin":
        role = "admin"
        bio = "adminuser"
    else:
        role = "user"
        bio = "normaluser"
    try:
        hashword = hash_pass(salt,password)
        db_input = Users(0,username,hashword,salt,role,bio)
        db.session.add(db_input)
        db.session.commit()
        return redirect(url_for('success'))
    except Exception as ex:
        abort(403)


@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/usermanage", methods=['GET','POST'])
@flask_login.login_required
def user_manage():
    if request.method == 'GET':
        return render_template('usermanager.html')

    old_password = request.form['password']
    new_password = request.form['new_pass']

    user = flask_login.current_user.u_name
    check = users_table.query.filter_by(u_name=user).first()
    if check.u_name != user:
        return "you're up to some shenanigans!"
    # hash old password
    old_hash = check.pj_salt
    old_pass = hash_pass(old_hash, old_password)
    if check.p_word != old_pass:
        return "your password did not match those on record, try again!"

    salt = gen_salt(check.u_name).hexdigest()
    password = hash_pass(salt, new_password)
    change_pass = users_table.query.filter_by(u_name=check.u_name).update(dict(p_word=password, pj_salt=salt))
    db.session.commit()

    return render_template('usermanager.html')


@app.route("/profile", methods=['GET','POST'])
@flask_login.login_required
def profile():
    user = flask_login.current_user.u_name
    prof = users_table.query.filter_by(u_name=user).first()
    if request.method == 'POST':
        biog = request.form['bio']
        new_bio = users_table.query.filter_by(u_name=user).update(dict(bio=biog))
        db.session.commit()
        return render_template("profile.html", output=prof.bio)

    return render_template("profile.html", output=prof.bio)


@app.route("/admin_search", methods=['GET','POST'])
@flask_login.login_required
def admin_search():
    user = flask_login.current_user.u_name
    permission = users_table.query.filter_by(u_name=user).first()

    if permission.role != "admin":
        abort(401)

    if request.method == 'GET':
        return render_template('admin_search.html')

    if request.method == 'POST':
        search = request.form['searchString']
        things = users_table.query.filter_by(u_name=search).first()
        return "Salt from searched user: %s" % things.pj_salt

    if things is None:
        return "No data found"

    return things


if __name__ == '__main__':
    app.run()


