#Controls main functionality of blog

import os
import webapp2
import jinja2
import re
import random
import string
import hashlib
import hmac
from google.appengine.ext import db

#Used to make hashes more secure
secret = "xsw321"

#Used for connecting templates with jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
#Creates jinja2 environment for loading templates
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


#Renders templates with jinja2
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
#Returns a beginning value and a secure hash value, to be used as a cookie in the Handler
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
#Makes sure the beginning values match
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val



#Basic request handling, slightly modified and copied from Udacity Intro to Backend course
class Handler(webapp2.RequestHandler):
    #Writes to webpage
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    #Renders Jinja template
    def render_str(self, template, **kw):
        kw['user'] = self.user
        return render_str(template, **kw)
    #Writes template to webpage
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    #Sets cookie name and value in default path
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    #Returns the cookie beginning value after it macthes the secure value
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    #Sets cookie to user id from the Google App Engine Database
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    #Sets cookie to None
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
    #Reads cookie and makes sure user is logged in for every page
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))



class LoginPage(Handler):
    self.render("login.html")

#Logs out user and redirects to homepage
class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class NewPostPage(Handler):
    self.render("newpost.html")

class PermaPage(Handler):
    self.render("permalink.html")

#Sorts posts on the home page by date created
class HomePage(Handler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('home.html', posts = posts)

#Generates 5 random letters for use in make_pw_hash method
def make_salt(length = 5):
    return ''.join(random.SystemRandom().choice(string.ascii_letters) for x in range(length))

#Generates and returns a secure hash value
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

#Compares hash values
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#Creates a users Key Object
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#Creates a blog Key Object
def blog_key(name):
    return db.Key.from_path('blogs', name)

#Stores information about users
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

#Stores information about posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    #Renders new posts
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class NewPostPage(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

class PostPage(Handler):
    self.render("post.html")

class SignupPage(Handler):
    self.render("sign-up.html")


#Basic valid username and password code, copied from Udacity Intro to Backend course
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



#Handles URI Routing
app = webapp2.WSGIApplication([(
                               )],
                              debug=True)
