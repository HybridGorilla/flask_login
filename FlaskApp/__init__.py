import urllib
import time
import hashlib
from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from flask import render_template
from flask import jsonify
import flask_bouncer as bouncer
from bouncer import authorization_method
import flask_login

app = Flask(__name__)
app.config.from_pyfile('instance/config.py')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'testlogin'


import FlaskApp.database
import FlaskApp.models
from FlaskApp.models import db
from FlaskApp.models import Users
users_table = Users
db.init_app(app)
t = time.time()


@authorization_method
def authorize(user, they):
    if user.is_admin:
        they.can(MANAGE, ALL)
    else:
        they.can(READ, ALL)


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


@app.route("/dbtest")
@flask_login.login_required
def dbtest():
    data = makeDict(users_table.query.all())
    return jsonify(data)


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


@app.route("/testlogin", methods=['GET','POST'])
def test_login():
    from flask import request
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userName = request.form['username']
        passWord = request.form['password']
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


@app.route("/admin")
@flask_login.login_required
def admin():
    return render_template("admin.html")


@app.errorhandler(500)
def server_error(error):
    return render_template("server_error.html")


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

    username = request.form['username']
    password = request.form['password']
    salt = gen_salt(username).hexdigest()

    hashword = hash_pass(salt,password)
    db_input = Users(0,username,hashword,salt)
    # u_role
    db.session.add(db_input)
    db.session.commit()
    return redirect(url_for('success'))


@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/usermanage", methods=['GET','POST'])
@flask_login.login_required
def user_manage():
    if request.method == 'GET':
        return render_template('user_manager.html')

    old_password = request.form['password']
    new_password = request.form['new_pass']

    return "You used a POST request!"


@app.route("/admin_search", methods=['GET','POST'])
@flask_login.login_required
def admin_search():
    if request.method == 'GET':
        return render_template('admin_search.html')

    if request.method == 'POST':
        search = request.form['searchString']
        things = users_table.query.filter_by(u_name=search).first()
        return "Salt from searched user: %s" % things.pj_salt

    if things is None:
        return "No data found"

    return things


@app.route("/testroles")
def roletest():
    k = flask_login.current_user.u_name
    print flask_login.current_user.is_authenticated()
    print ("Current Flask User: %s" % k)
    x = users_table.query.filter_by(u_name=k).first()

    if k is None:
        flask_login.current_user = "anon"

    if x != "admin":
        return x.u_name + " " + x.role + " Rejected"
    else:
        return x.u_name + " " + x.role + " Granted!"


if __name__ == '__main__':
    app.run()


