from flask import send_from_directory, render_template, request, redirect, flash, session, make_response, url_for
from flask import current_app as app
import os, requests, yaml
from yaml import Loader
import lxml.etree
from . import db, models
from functools import wraps
import markdown as md
from faker import Faker
from faker.providers import profile,misc
import glob
from sqlalchemy import text

def get_base_url(req):
    if 'X-Forwarded-Host' in req.headers:
        return '{}://{}'.format(req.headers['X-Forwarded-Proto'], req.headers['X-Forwarded-Host'])
    else:
        return ''

def is_authenticated():
    try:
        return session["auth"] == True
    except:
        return False

def is_admin():
    return is_authenticated() and  session["user"]["role"] == "admin"

def me():
    return session['user']

@app.template_filter()
def markdown(input):
    return md.markdown(input, extensions=['codehilite', 'fenced_code'])

app.jinja_env.globals.update(is_authenticated=is_authenticated)
app.jinja_env.globals.update(is_admin=is_admin)
app.jinja_env.globals.update(me=me)

def authenticated(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if is_authenticated():
            return f(*args, **kwargs)
        else:
            return redirect("/", code=302)
    return decorated

def list_files_dir():
    path_dir = os.path.join(os.path.dirname(__file__),"files")
    return os.listdir(path_dir)

@app.route('/assets/<path:path>')
def send_js(path):
    return send_from_directory('assets', path)

@app.route('/')
def index():
    return render_template("index.html",title="Demo App")

@app.route('/cwe-23')
def get_cwe_23():
    return render_template("pathtraversal.html",lst=list_files_dir(),title="CWE-23 : Relative Path Traversal")

@app.route('/cwe-918')
def get_cwe_918():
    return render_template("ssfr.html",title="CWE-918 : Server-Side Request Forgery (SSRF)")

@app.route('/a4-xxe')
def get_a4_xxe():
    return render_template("xxe.html",title="A4 - XML External Entities (XXE)")

@app.route('/a8-deserialization')
def get_a8_deserialization():
    return render_template("deserialization.html",title="A8 - Insecure Deserialization")

@app.route('/a1-injection')
def get_a1_injection():
    return render_template("injection.html",title="A1 - Injection")

@app.route('/a7-xss')
def get_a7_xss():
    comments = models.Comment.query.all()
    if request.args.get('name'):
        return render_template("xss.html",comments=comments,name=request.args['name'],title="A7 - Cross-Site Scripting (XSS)")
    else:
        return render_template("xss.html",comments=comments,title="A7 - Cross-Site Scripting (XSS)")

@app.route('/a7-xss-csp')
def get_a7_xss_csp():
    comments = models.Comment.query.all()
    if request.args.get('name'):
        resp = make_response(render_template("xss-csp.html",comments=comments,name=request.args['name'],title="A7 - Cross-Site Scripting (XSS)"))
        resp.headers['Content-Security-Policy']="script-src 'self' https://*.google.com; object-src 'none';"
    else:
        resp = make_response(render_template("xss-csp.html",comments=comments,title="A7 - Cross-Site Scripting (XSS)"))
    return resp

@app.route('/cwe-434')
def get_cwe_434():
    return render_template("upload.html",title="CWE-434 : Unrestricted file upload")


@app.route('/cwe-434',methods=['POST'])
def post_cwe_434():
    file = request.files['file']
    path_file = os.path.join(os.path.dirname(__file__),"files",file.filename)
    file.save(path_file)
    return render_template("upload.html",path_file=path_file,title="CWE-434 : Unrestricted file upload")

@app.route('/a7-xss',methods=['POST'])
def post_a7_xss():
    
    c = models.Comment(name=request.form['name'],comment=request.form['comment'])
    db.session.add(c)
    db.session.commit()
    comments = models.Comment.query.all()
    return render_template("xss.html",comments=comments,title="A7 - Cross-Site Scripting (XSS)")

@app.route('/a1-injection',methods=['POST'])
def post_a1_injection():
    try:
        query = "SELECT * FROM user WHERE id={}".format(request.form['id'])
        result = db.session.execute(text(query))
    except Exception as e:
        return  render_template("injection.html",query=str(e),result=[],title="A1 - Injection", id=request.form['id']), 500

    return render_template("injection.html",query=query,result=result,title="A1 - Injection", id=request.form['id'])

@app.route('/a8-deserialization',methods=['POST'])
def post_a8_deserialization():
    y = yaml.load(request.form['document'], Loader=Loader)
    return render_template("deserialization.html",article={"title":y['article']['title'],"content":y['article']['content']},title="A8 - Insecure Deserialization")

@app.route('/a4-xxe',methods=['POST'])
def post_a4_xxe():
    parser = lxml.etree.XMLParser(no_network=False)
    root = lxml.etree.fromstring(request.form['document'],parser)
    title = ""
    content = ""
    for child in root:
        if child.tag=="title":
            title = child.text
        if child.tag=="content":
            content = child.text
    return render_template("xxe.html",article={"title":title,"content":content},title="A4 - XML External Entities (XXE)")

@app.route('/cwe-918',methods=['POST'])
def post_cwe_918():
    return render_template("ssfr.html",site_content=requests.get(request.form['url']).text,title="CWE-918 : Server-Side Request Forgery (SSRF)")

@app.route('/cwe-23',methods=['POST'])
def post_cwe_23():
    file_path = os.path.join(os.path.dirname(__file__),"files",request.form['file'])
    with open(file_path, 'r') as fd:
        content = fd.read()
    return render_template("pathtraversal.html",file_content=content,file_path=file_path,lst=list_files_dir(),title="CWE-23 : Relative Path Traversal")

@app.route('/login')
def get_login():
    return render_template("login.html",title="Login")

@app.route('/login',methods=["POST"])
def post_login():
    try:
        query = "SELECT * FROM user WHERE email='{}' AND password='{}'".format(request.form['email'], request.form['password'])
        user = db.session.execute(text(query)).first()
    except Exception as e:
        return  render_template("login.html",title="Login", query=str(e), email=request.form['email'], password=request.form['password']), 500
    
    if user:
        session["auth"] = True
        session["user"] = {"id":user.id,"name":user.name,"email":user.email,"role":user.role}
        return redirect(get_base_url(request)+"/", code=302)    
    else:
        flash(u'Invalid login or password provided', 'danger')
    return render_template("login.html",title="Login", query=query, email=request.form['email'], password=request.form['password'])

@app.route('/register')
def get_register():
    return render_template("register.html",title="Register")

@app.route('/register',methods=["POST"])
def post_register():
    if 'name' in request.form and 'password' in request.form and 'email' in request.form:
        login = models.User.query.filter_by(email=request.form['email']).first()
        if not login:
            try:
                db.session.add(models.User(name=request.form['name'],password=request.form['password'], email=request.form['email']))
                db.session.commit()
                login = models.User.query.filter_by(email=request.form['email']).first()
                session["auth"] = True
                session["user"] = {"id":login.id,"name":login.name,"email":login.email,"role":login.role}
                return redirect(get_base_url(request)+"/", code=302)
            except:
                flash(u'Error during the registration process', 'danger')
        else:
            flash(u'Email already taken', 'danger')
    return redirect(get_base_url(request)+"/register", code=302)

@app.route('/logout')
def get_logout():
    session["auth"] = False
    session["user"] = None
    return redirect(get_base_url(request)+"/", code=302)

@app.route('/profile')
@authenticated
def get_profile():
    login = models.User.query.filter_by(id=session["user"]["id"]).first()
    return render_template("profile.html",title="My Profile",user=login)

@app.route('/profile/<int:id>')
@authenticated
def get_profile_with_id(id):
    login = models.User.query.filter_by(id=id).first()
    return render_template("profile.html",title="My Profile",user=login)

@app.route('/profile/<int:id>',methods=["POST"])
@authenticated
def post_profile_with_id(id):
    if 'password' in request.form:
        login = models.User.query.filter_by(id=request.form['id']).first()
        login.password = request.form['password']
        db.session.commit()
        flash(u'Password updated', 'success')
    elif 'email' in request.form and 'name' in request.form and 'job' in request.form:
        not_existing = models.User.query.filter_by(id=request.form['email']).first()
        login = models.User.query.filter_by(id=id).first()
        if not not_existing or login.email == request.form['email']:
            try:
                login.email = request.form['email']
                login.name = request.form['name']
                login.job = request.form['job']
                db.session.commit()
                if session["user"]["id"]==login.id:
                    session["auth"] = True
                    session["user"] = {"id":login.id,"name":login.name,"email":login.email,"role":login.role}
                flash(u'Profile updated', 'success')
            except:
                flash(u'Error during the profile edition process', 'danger')
        else:
            flash(u'Email already taken', 'danger')
    return redirect(request.referrer, code=302)

@app.route('/profile',methods=["POST"])
@authenticated
def post_profile():
    return post_profile_with_id(session["user"]["id"])

@app.route('/list')
@authenticated
def get_list():
    if "promote" in request.args:
        if is_admin():
            login = models.User.query.filter_by(id=request.args['promote']).first()
            login.role = "admin"
            db.session.commit()
            flash(u'User "{}" has now the "admin" role'.format(login.email), 'success')
        else:
            flash(u'You do not have the "admin" role', 'danger')
    if "downgrade" in request.args:
        if is_admin():
            login = models.User.query.filter_by(id=request.args['downgrade']).first()
            login.role = "user"
            db.session.commit()
            flash(u'User "{}" has now the "user" role'.format(login.email), 'success')
        else:
            flash(u'You do not have the "admin" role', 'danger')
    return render_template("list.html",title="Members list",users=models.User.query.all())

@app.route('/reset')
def get_reset():
    return render_template("reset.html",title="Reset The App")

@app.route('/reset',methods=["POST"])
def post_reset():
    if request.form['kind'] == "database":
        fake = Faker()
        fake.add_provider(profile)
        fake.add_provider(misc)

        db.drop_all()
        db.create_all()
        for i in range(10):
            p = fake.profile(fields=None, sex=None)
            u = models.User(name=p['name'],job=p['job'],password=fake.password(length=10), email=p['mail'])
            db.session.add(u)
            db.session.commit()
        p = fake.profile(fields=None, sex=None)
        admin = models.User(name='admin',job=p['job'],password=fake.password(length=10), email=p['mail'], role="admin")
        db.session.add(admin)
        db.session.commit()
        flash(u'Database reset.', 'success')
    
    if request.form['kind'] == "files":
        import glob

        files = glob.glob(os.path.join(os.path.dirname(__file__),"files",'**'))
        for f in files:
            if f.replace(os.path.join(os.path.dirname(__file__),"files"),"") not in ['/file1', '/file2']:
                os.remove(f)
        flash(u'Files removed', 'success')
    return render_template("reset.html",title="Reset The App")