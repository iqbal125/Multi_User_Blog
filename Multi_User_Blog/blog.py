#Controls main functionality of blog

from time import strftime
import os
import webapp2
import jinja2
import re
import random
import string
import hashlib
import hmac
from google.appengine.ext import db
import time

"""
        The Main Handler Class and Associated Methods
"""

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

#Returns a beginning value and a hmac value, to be used as a cookie in the Handler
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#Makes sure hash values match
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Basic request handling, modified and copied from Udacity Intro to Backend course
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
    #Reads cookie and sets user to that user id
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


"""

        Classes to Handle the Requests

"""

class HomePage(Handler):
    def get(self):
        self.render("home.html")

class BlogPage(Handler):
    def get(self):
        posts = Post.all().order("-created")
        self.render('blog.html', posts = posts)

class ResourcePage(Handler):
    def get(self):
        self.render("resources.html")

class AboutPage(Handler):
    def get(self):
        self.render("about.html")

"""

    Handles User Requests

"""

class SignupPage(Handler):
    def get(self):
        self.render("sign-up.html")

    def post(self):
        #Gets username, password, email
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)
        #Checks if username is valid otherwise returns error
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('sign-up.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignupPage):
    def done(self):
        #Makes sure user doesnt already exist, then creates and logs in new user
        u = User.by_name(self.username)
        if u:
            msg = 'Error: That user already exists.'
            self.render('sign-up.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class LoginPage(Handler):
    def get(self):
        self.render("login.html")
    #Gets username and password
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        #If valid username and password logs in user, otherwise prints error message
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Error: Invalid login'
            self.render('login.html', error = msg)

#Calls logout method in the Handler and redirects to homepage
class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

"""

    Handles Requests for Posts

"""

class NewPostPage(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        user = self.user
        subject = self.request.get('subject')
        content = self.request.get('content')
        #If there is subject and content, the Post class creates a new post and redirects to a permalink
        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = str(user.name))
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "Error: Subject and Content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class EditPost(Handler):
    def get(self, post_id):
        #Gets post id
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if post:
            self.render("editpost.html", post=post)
        else:
            self.write("Error: Post doesn't exist")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = self.request.get("subject")
        content = self.request.get('content')
        user = self.user
        #If the user is the author. Theres is subject and content, the post is updated. Otherwise error.
        if user.name == post.author:
            if content and subject:
                post = Post.get_by_id(int(post_id), parent=blog_key())
                if post:
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.2)
                    self.redirect('/post/%s' %  str(post_id))
                else:
                    self.write("Error: Post doesnt Exist")
            else:
                error = "Content and subject, please!"
        else:
            self.write("Error: Can not edit other user's post")


class PostPage(Handler):
    def get(self, post_id):
        #Creates key for specific post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #Gets the key for a specific post
        post = db.get(key)
        #Gets all the comments and filters by matching the post id
        comments = Comment.all().order("-created")
        comments.filter("post_id =", str(post_id))

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments = comments)
    #Adds a like when "like" input value is submitted
    def post(self):
        user = self.user
        if self.request.get("like"):
            L = Like(like_postid = post_id, like_author = user.name, like_num = like_num + 1)
            L.put()

class DeletePost(Handler):
    def get(self, post_id):
        #Creates key for a specific post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #Gets the key for a specific post
        post = db.get(key)
        if post:
            self.render("deletepost.html", post=post)
        else:
            self.write("Error: Post doesn't Exist")

    def post(self, post_id):
        user = self.user
        #Creates Key for a specific post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #Gets the key for a specific post
        post = db.get(key)

        #Checks if the author is the user and then deletes the post
        if post:
            print post.subject
            if post.author == user.name:
                post.delete()
                self.redirect('/blog')
            else:
                self.write("Error: Can't Delete other User's Post")
        else:
            self.write("Error: Post doesen't Exist")

"""

    Handles Requests for Comments

"""

class DeleteComment(Handler):
    def post(self, comment_id):
        user = self.user
        #Gets comment entity by its datastore id
        comment = Comment.get_by_id(int(comment_id))
        #Checks if the author is the user, then deletes the comment
        if comment:
            if comment.author == user.name:
                comment.delete()
                self.redirect('/post/%s' %  str(comment.post_id))
            else:
                 self.write("Error: You cannot delete other user's comments")
        else:
             self.write("Error: This comment no longer exists")

class AddComment(Handler):
    def post(self):
        if not self.user:
            self.redirect('/login')

        post_id = self.request.get("post_id")
        content = self.request.get('content')
        user = self.user
        #Get input from user and creates a new comment
        if content:
            c = Comment(content = content, author = user.name, post_id = post_id)
            c.put()
            time.sleep(0.2)
            self.redirect('/post/%s' % str(post_id))
        else:
            error = "Content, please!"

class EditComment(Handler):
    def get(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            time.sleep(0.2)
            self.render("editcomment.html", comment=comment)
        else:
            self.write('Error: Comment doesnt Exist')

    def post(self, comment_id):
        if not self.user:
            self.redirect('/login')

        content = self.request.get('content')
        user = self.user
        #Gets a comment, then updates the content
        if content:
            comment = Comment.get_by_id(int(comment_id))
            if comment:
                comment.content = content
                comment.put()
                time.sleep(0.2)
                self.redirect('/post/%s' %  str(comment.post_id))
            else:
                self.write("failed")
        else:
            error = "Content, please!"



"""

        Methods to Make Password Hashes

"""

#Generates 5 random letters for use in make_pw_hash method
def make_salt(length = 5):
    return ''.join(random.SystemRandom().choice(string.ascii_letters) for x in range(length))

#Generates and returns a secure hash value
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

#Makes sure database hash matches user hash
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#Creates a users Key Object
def users_key(name = "default"):
    return db.Key.from_path('users', name)

#Creates a blog Key Object
def blog_key(group="default"):
    return db.Key.from_path('blogs', group)


"""

        The User, Post, Comment and Like Models

"""

#User entity with name, password hash and optional email properties
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #Returns a user by their id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    #Returns a user by their name
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    #Returns a new user
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    #Looks up a user by name, and if the user is valid returns the user
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#Post entity with subject, content and created date properties
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty()

    #Returns a post by its id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = blog_key)


#Comment entity with content and author properties
class Comment(db.Model):
    content = db.StringProperty(required = True)
    author = db.StringProperty()
    post_id = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    #Helper Method to add comments
    @classmethod
    def addComment(cls, content, author):
        c = Comment(content = str(content),
                   comment_text = str(text),
                   author = str(author))
        c.put()
        return c.key().id()

#Like Entity with author, id number and number of likes
class Like(db.Model):
    like_author = db.StringProperty()
    like_postid = db.TextProperty(required = True)
    like_num = db.IntegerProperty(default = 0)


"""

        Username and Password Validation

"""

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



"""

        Handles URI Routing

"""

app = webapp2.WSGIApplication([('/', HomePage),
                               ("/blog", BlogPage),
                               ("/resources", ResourcePage),
                               ("/about", AboutPage),
                               ("/deletepost/([0-9]+)", DeletePost),
                               ("/deletecomment/([0-9]+)", DeleteComment),
                               ("/editpost/([0-9]+)", EditPost),
                               ("/editcomment/([0-9]+)", EditComment),
                               ('/post/([0-9]+)', PostPage),
                               ('/newpost', NewPostPage),
                               ('/newcomment', AddComment),
                               ('/signup', Register),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage)
                               ],
                              debug=True)
