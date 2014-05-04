import os
import webapp2
import hmac
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
import re
import json
import logging
import datetime
import time
import urllib2
import HTMLParser
import pafy


USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):    
  return USER_RE.match(username) 

def valid_password(password):
  return PASSWORD_RE.match(password) 

def valid_verify(password,verify):
  return password==verify

def valid_email(email):
  return EMAIL_RE.match(email) or email==''

def get_users() :
      return list(db.GqlQuery("SELECT * from Users"))

def user_exists(username) :  
  for user in get_users():
    if username == user.user_id:
      return True    

def password_match(username,password) :  
  for user in get_users() :
    if username == user.user_id and user.password == password :
      return True         
  return False    

def valid_form(username,password,verify,email) :
  return valid_username(username) and valid_password(password) and valid_verify(password,verify) and valid_email(email) and not user_exists(username)

def hash_str(s):
    return hmac.new('lobo',s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def get_posts(update = False) :
    key = 'posts'        
    posts = memcache.get(key)
    SAVED_TIME = memcache.get('age')
    if not SAVED_TIME :
        update = True
    if posts is None or update :        
        logging.error('DB read')  
        SAVED_TIME = datetime.datetime.now().utcnow()
        posts = list(db.GqlQuery('SELECT * from Post order by post_date desc'))
        memcache.set(key,posts)
        memcache.set('age',SAVED_TIME)
    return posts,SAVED_TIME

def set_posts(subject,content) :
    logging.error('DB write')   
    post = Post(subject = subject, content = content).put() 
    time.sleep(.1)
    get_posts(True)
    return post

def age_str(SAVED_TIME) :    
    return "queried %s seconds ago"%int((datetime.datetime.now().utcnow() - SAVED_TIME).total_seconds())

   
jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def ret_template(template):
    return jinja_environment.get_template(template)

def return_primary_results(search_json):

    primary_results = {}
    if not search_json["Definition"] == "" : 
        if not search_json["Definition"].find("definition:") == -1 :
            primary_results["definition"] = search_json["Definition"][search_json["Definition"].find("definition:")+len("definition")+1:]
        else :
            primary_results["definition"] = search_json["Definition"]
        primary_results["definition_source"] = search_json["DefinitionSource"]
        primary_results["definition_url"] = search_json["DefinitionURL"]

    if not search_json["AbstractURL"] == "" : 
        primary_results["abstract_text"] = search_json["AbstractText"]
        primary_results["abstract_source"] = search_json["AbstractSource"]
        primary_results["abstract_url"] = search_json["AbstractURL"]
        
    if not search_json["Image"] == "" : 
        primary_results["image_url"] = search_json["Image"]

    if not search_json["Answer"] == "" : 
        primary_results["instant_answer"] = search_json["Answer"]  
        if search_json["AnswerType"] == "calc" :
            calc_start_loc = search_json["Answer"].find("focus();\">")+len("focus();\">")
            calc_remaining_array = search_json["Answer"][calc_start_loc+1:]
            calc_end_loc = calc_remaining_array.find("</a>")
#            logging.error(calc_start_loc)
#            logging.error(calc_end_loc)
#            logging.error(calc_remaining_array)
#            logging.error(search_json["Answer"][calc_start_loc:calc_start_loc+calc_end_loc+1])
            primary_results["instant_answer"] = search_json["Answer"][calc_start_loc:calc_start_loc+calc_end_loc+1]

    if search_json["AnswerType"] == "root" :
            root_start_loc = search_json["Answer"].find("focus();\">")+len("focus();\">")
            root_remaining_array = search_json["Answer"][root_start_loc+1:]
            root_end_loc = root_remaining_array.find("</a>")            
            primary_results["instant_answer"] = search_json["Answer"][root_start_loc:root_start_loc+root_end_loc+1]


    if not search_json["Results"] == [] :
        primary_results["results_list"] = search_json["Results"]
        #logging.error(search_json["Results"])


    if not search_json["RelatedTopics"] == [] :
        JSON_APPEND = "&format=json"
        primary_results["related_topics_list"] = search_json["RelatedTopics"]
        for e in primary_results["related_topics_list"] :
            if "Result" in e.keys() :
                #logging.error(e['FirstURL'])
                heading = json.loads(urllib2.urlopen(e['FirstURL']+JSON_APPEND).read())["Heading"]
                #logging.error(heading)
               # heading = e["Text"]

                #if not heading.find(' or') == -1 :
                 #   heading = heading[:e["Text"].find(' or')]

                #logging.error(heading)
                    
                #if not heading.find(',') == -1 :
                 #   heading = heading[:e["Text"].find(',')]   

                #if not heading.find(' - ') == -1 :
                 #   heading = heading[:e["Text"].find(' - ')]                                 

                logging.error(heading)
                e["FirstURL"] = heading


    return primary_results

def return_news_results(search_string, user_ip) :
    html_parser = HTMLParser.HTMLParser()
    search_string =  search_string.replace(' ','%20')
    logging.error(search_string)
    url = urllib2.urlopen("https://ajax.googleapis.com/ajax/services/search/news?v=1.0&q=%s&userip=%s"%(search_string,user_ip)).read()
    news_json = json.loads(url)
    logging.error(news_json)
    news_results = []    
    for e in news_json["responseData"]["results"] :
        news_results.append({"title":html_parser.unescape(e["titleNoFormatting"]) ,"url" : e["unescapedUrl"], "publisher":e["publisher"]})
       
    logging.error(news_results)    
    more_news_results = []
    for e in news_json["responseData"]["results"] :
        if "relatedStories" in e.keys() :
            for i in e["relatedStories"] :
                more_news_results.append({"title":html_parser.unescape(e["titleNoFormatting"]) ,"url" : e["unescapedUrl"] })    


    key = "&key=RiMKJK3gq2FTBWxx41B76MR2OHc_"
    url = urllib2.urlopen("http://www.faroo.com/api?q=%s&start=1&length=10&l=en&src=news&i=true&f=json%s"%(search_string,key)).read()
    news_json = json.loads(url)
 #   logging.error(json_response)    
    for e in news_json["results"] :
        more_news_results.append({"title":html_parser.unescape(e["title"]) ,"url" : e["url"] })
    
    return {"news_results" : news_results , "more_news_results" : more_news_results}  

def return_top_results(search_string, user_ip) :
    html_parser = HTMLParser.HTMLParser()
    search_string =  search_string.replace(' ','%20')
    logging.error(search_string)
    url = urllib2.urlopen("https://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=%s&userip=%s"%(search_string,user_ip)).read()
    top_json = json.loads(url)
    logging.error(top_json)
    top_results = []    
    for e in top_json["responseData"]["results"] :
        top_results.append({"title":html_parser.unescape(e["titleNoFormatting"]) ,"url" : e["unescapedUrl"] })
       
    logging.error(top_results)    
    return {"top_results" : top_results}         


def return_web_results(search_string, user_ip) :
    html_parser = HTMLParser.HTMLParser()
    search_string =  search_string.replace(' ','%20')
    logging.error(search_string)
 #   logging.error(json_response)
    web_results = []  
    more_web_results = []  
    key = "&key=RiMKJK3gq2FTBWxx41B76MR2OHc_"
    url = urllib2.urlopen("http://www.faroo.com/api?q=%s&start=1&length=10&l=en&src=web&i=true&f=json%s"%(search_string,key)).read()
   # json_response = unirest.get("https://faroo-faroo-web-search.p.mashape.com/api?q=lobo",
  
 # headers={
   # "X-Mashape-Authorization": "ArSWXeNxgohO7uPTFIGzNO79TNjPyYNW"
  #}
#);
    web_json = json.loads(url)
 #   logging.error(json_response)    
    for e in web_json["results"] :
        if len(web_results) < 4 :        
            web_results.append({"title":html_parser.unescape(e["title"]) ,"url" : e["url"] })

        else :
            more_web_results.append({"title":html_parser.unescape(e["title"]) ,"url" : e["url"] })


    url = urllib2.urlopen("http://188.40.64.7:8092/yacysearch.json?query=%s"%(search_string)).read()
   # json_response = unirest.get("https://faroo-faroo-web-search.p.mashape.com/api?q=lobo",
  
 # headers={
   # "X-Mashape-Authorization": "ArSWXeNxgohO7uPTFIGzNO79TNjPyYNW"
  #}
#);
    web_json = json.loads(url)

    for e in web_json["channels"][0]["items"] :
        if len(web_results) < 4 :       
            web_results.append({"title":html_parser.unescape(e["title"]) ,"url" : e["link"] })
        
        else :
            more_web_results.append({"title":html_parser.unescape(e["title"]) ,"url" : e["link"] })

    #logging.error(web_results)   

     
    return {"web_results" : web_results, "more_web_results" : more_web_results}    

def return_image_results(search_string,user_ip) :
    html_parser = HTMLParser.HTMLParser()
    search_string =  search_string.replace(' ','%20')
    logging.error(search_string)
    url = urllib2.urlopen("https://ajax.googleapis.com/ajax/services/search/images?v=1.0&q=%s&userip=%s"%(search_string,user_ip)).read()
    image_json = json.loads(url)
    #logging.error(image_json)
    image_results = []    
    for e in image_json["responseData"]["results"] :
        image_results.append({"title":html_parser.unescape(e["content"]) ,"url" : e["unescapedUrl"] })
       
    #logging.error(image_results)    
    return {"image_results" : image_results}      


def return_thored_results(search_string, user_ip) :
    search_string =  search_string.replace(' ','%20')
    url = urllib2.urlopen("http://suggestqueries.google.com/complete/search?client=firefox&q=%s"%(search_string)).read()
    thored_json = json.loads(url)
    thored_results = []
    for e in thored_json[1] :
        thored_results.append({"result" : e})
    return {"thored_results" : thored_results}   

def return_video_resutls(search_string , user_ip) :
    html_parser = HTMLParser.HTMLParser()
    search_string =  search_string.replace(' ','%20')
    logging.error(search_string)
    url = urllib2.urlopen("https://ajax.googleapis.com/ajax/services/search/video?v=1.0&q=%s&userip=%s"%(search_string,user_ip)).read()
    video_json = json.loads(url)
    #logging.error(image_json)
    video_results = [] 
    for e in video_json["responseData"]["results"] :
        video_results.append({"title":html_parser.unescape(e["titleNoFormatting"]) ,"url" : "//www.youtube.com/embed/"+re.findall( r'v\=([\-\w]+)', e["url"] )[0] , 'vid' : re.findall( r'v\=([\-\w]+)', e["url"] )[0] ,'source' : e["url"]})
        logging.error(e["url"])       
        logging.error( "//www.youtube.com/embed/"+re.findall( r'v\=([\-\w]+)', e["url"] )[0])  

    return {"video_results" : video_results}     

    

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    post_date = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    user_id = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    join_date = db.DateTimeProperty(auto_now_add = True)    


class BlogPage(webapp2.RequestHandler):
    def get(self):        
        posts = get_posts()[0]
        SAVED_TIME = get_posts()[1]
        template_values = {
            'posts' : posts ,
            'age_str' : age_str(SAVED_TIME)
            
        }
        self.response.out.write(ret_template('blog.html').render(template_values))

class BlogPageJsonHandler(BlogPage):
    def  get(self):        
        self.response.content_type = 'application/json; charset=utf-8'
        posts = get_posts()
        post_list = []

        for post in posts :
            post_list.append({"subject":post.subject,"content":post.content,"created":str(post.post_date)})
        j = json.dumps(post_list)    
        self.response.out.write(j)

class FormHandler(webapp2.RequestHandler):
    def get(self):
        template_values = {
            'subject': '',
            'content': '',
            
        }
        self.response.out.write(ret_template('form.html').render(template_values))

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        template_values = {
            'subject': subject,
            'content': content,

        }           
        
        if subject and content :
            post_key = set_posts(subject, content)                        
            self.redirect("/blog/"+str(post_key.id()))

        else :
            template_values['error'] = 'Enter both content and subject'
            self.response.out.write(ret_template('form.html').render(template_values)) 

class ThanksHandler(webapp2.RequestHandler):
    def get(self , post_key): 

        post = memcache.get(post_key)
        SAVED_TIME = memcache.get('%s|age'%post_key)
        if post is None or not SAVED_TIME :         
            SAVED_TIME = datetime.datetime.now().utcnow()
            post = Post.get_by_id(int(post_key))
            memcache.set(post_key,post)
            memcache.set('%s|age'%post_key,SAVED_TIME)    
        
        template_values = {
            'subject': post.subject,
            'content': post.content,
            'post_date': post.post_date,
            'key' : post_key,
            'age_str' : age_str(SAVED_TIME)
        }

        self.response.out.write(ret_template('thanks.html').render(template_values))

class ThanksJsonHandler(webapp2.RequestHandler):
    def get(self , post_key) :       
        post = Post.get_by_id(int(post_key))
        post_dict = {"subject":post.subject,"content":post.content,"created":str(post.post_date)}
        j = json.dumps(post_dict)
        self.response.content_type = 'application/json; charset=utf-8'
        self.response.out.write(j)

class SignupHandler(webapp2.RequestHandler):
    def get(self) :             
        template_values = {
                            'name' : '',
                            'usererror' : '' ,
                            'password' : '', 
                            'passworderror': '', 
                            'verify' : '' , 
                            'verifyerror': '' , 
                            'email': '',
                            'emailerror':''
                          }        
        self.response.out.write(ret_template('sign.html').render(template_values))

    def post(self) :
        name=self.request.get('username')
        usererror = ''
        password=self.request.get('password')    
        passworderror = ''
        verify=self.request.get('verify')
        verifyerror=''
        email=self.request.get('email')
        emailerror=''
        if not valid_username(name) :
          usererror = "That's not a valid username."   
        if user_exists(name) :
          usererror =  "That user already exists!"   
        if not valid_password(password):
          passworderror = "That wasn't a valid password."  
        if not valid_verify(password,verify) and valid_password(password):
          verifyerror = "Your passwords didn't match."  
        if not valid_email(email):
          emailerror = "That's not a valid email."      
        
        if not valid_form(name,password,verify,email) : 
            template_values = {
                                'name' : name,
                                'usererror' : usererror ,
                                'password' : '', 
                                'passworderror': passworderror, 
                                'verify' : '' , 
                                'verifyerror': verifyerror , 
                                'email': email,
                                'emailerror':emailerror
                              }     
            self.response.out.write(ret_template('sign.html').render(template_values))   
        
        else :

            self.response.headers.add_header('Set-Cookie', 'user_id='+make_secure_val(str(name))+'; Path = /')
            u = Users(user_id=name, email=email, password=password)
            u.put()
            
            self.redirect('/welcome')

class LoginHandler(webapp2.RequestHandler):
    def get(self) :
        template_values = {
                            'name' : '',                       
                            'password' : '',                     
                            'error':''
                          }          

        self.response.out.write(ret_template('login.html').render(template_values)) 
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        error = ''
        if user_exists(username) :
            if password_match(username,password) :
                self.response.headers.add_header('Set-Cookie', 'user_id='+make_secure_val(str(username))+';Path = /')
                self.redirect('/welcome')

            else :
                error = 'Invalid Login' 

        else :           
            error = 'Invalid Login'        


        template_values = {    'name' : '',                       
                               'password' : '',                     
                               'error': error
                               }          

        self.response.out.write(ret_template('login.html').render(template_values))   

class LogoutHandler(webapp2.RequestHandler) :
    def get(self):
        self.response.headers.add_header("Set-Cookie","user_id="+';Path = /')
        self.redirect('/signup')                                     

class WelcomeHandler(webapp2.RequestHandler):
    def get(self) :        
        user_cookie = self.request.cookies.get('user_id')
        if check_secure_val(user_cookie) == user_cookie.split('|')[0]:
            template_values = {'username' : user_cookie.split('|')[0]}
            self.response.out.write(ret_template('welcome.html').render(template_values))

        else :
            self.redirect('/signup')    

class FlushHandler(webapp2.RequestHandler) :
    def get(self) :
        memcache.flush_all()
        self.redirect('/')          

class SearchHandler(webapp2.RequestHandler) :
    def get(self, search_string="") :
        search_string = self.request.get('search_string')
        logging.error(search_string)
        template_values={"tr_show_value" : 'hidden' , "sr_show_value" : 'hidden' , "mr_show_value" : 'hidden'}
        self.response.out.write(ret_template('test.html').render(template_values))

    def post(self):
        search_string = self.request.get('search_string')       
        user_ip = self.request.remote_addr 
        if search_string == "" :
            template_values={'search_string':search_string , "tr_show_value" : 'hidden' , 
                             "mr_show_value" : 'hidden' ,
                             "sr_show_value" : 'hidden'}
        else :
            template_values={'search_string':search_string}

            url = 'http://api.duckduckgo.com/?q=%s&format=json'%search_string.replace(' ','%20')
            url_content = urllib2.urlopen(url).read()
            search_json = json.loads(url_content)
            logging.error(search_json)
            try :
                primary_results = return_primary_results(search_json)
            except :
                primary_results = {}

            news_results = return_news_results(search_string , user_ip)
            top_results = return_top_results(search_string , user_ip)
            web_results = return_web_results(search_string , user_ip)
            image_results = return_image_results(search_string , user_ip)
            thored_results = return_thored_results(search_string , user_ip)
            video_results = return_video_resutls(search_string, user_ip)
            template_values = dict(template_values.items() + 
                                   primary_results.items() + 
                                   news_results.items() +
                                   top_results.items() +
                                   web_results.items()  +
                                   image_results.items() +
                                   thored_results.items() +
                                   video_results.items()
                                   )

        template_values['search_string'] = search_string
        self.response.out.write(ret_template('test.html').render(template_values))  

class ShareHandler(webapp2.RequestHandler) :
    def get(self) :
        #add = self.request.remote_addr        
        template_values = {}
        self.response.out.write(ret_template('share.html').render(template_values))


class TestHandler(webapp2.RequestHandler):
    def get(self, search_string="") :
        search_string = self.request.get('search_string')
        logging.error(search_string)
        template_values={"tr_show_value" : 'hidden' , "sr_show_value" : 'hidden' , "mr_show_value" : 'hidden'}
        self.response.out.write(ret_template('test.html').render(template_values))

    def post(self):
        search_string = self.request.get('search_string')       
        user_ip = self.request.remote_addr 
        if search_string == "" :
            template_values={'search_string':search_string , "tr_show_value" : 'hidden' , 
                             "mr_show_value" : 'hidden' ,
                             "sr_show_value" : 'hidden'}
        else :
            template_values={'search_string':search_string}

            url = 'http://api.duckduckgo.com/?q=%s&format=json'%search_string.replace(' ','%20')
            url_content = urllib2.urlopen(url).read()
            search_json = json.loads(url_content)
            logging.error(search_json)
            try :
                primary_results = return_primary_results(search_json)
            except :
                primary_results = {}

            news_results = return_news_results(search_string , user_ip)
            top_results = return_top_results(search_string , user_ip)
            web_results = return_web_results(search_string , user_ip)
            image_results = return_image_results(search_string , user_ip)
            thored_results = return_thored_results(search_string , user_ip)
            video_results = return_video_resutls(search_string, user_ip)
            template_values = dict(template_values.items() + 
                                   primary_results.items() + 
                                   news_results.items() +
                                   top_results.items() +
                                   web_results.items()  +
                                   image_results.items() +
                                   thored_results.items() +
                                   video_results.items()
                                   )

        template_values['search_string'] = search_string
        self.response.out.write(ret_template('test.html').render(template_values)) 

class DownloadHandler( webapp2.RequestHandler) :
    def get(self) :
        vid = self.request.get('vid')
        logging.error(vid)
        url = "http://www.youtube.com/watch?v=%s"%vid
        video  = pafy.new(url)
        streams = video.allstreams        
        template_values = { "url" : url , 
                            "vid" : vid ,
                            "video" : video,                            
                            "streams" : streams
                            }                             
        self.response.out.write(ret_template('downloader.html').render(template_values))        

    def post(self) :
        pass    

def handle_404(request, response, exception):
    logging.exception(exception)
    response.write(ret_template('404.html').render({}))
    response.set_status(404)

def handle_500(request, response, exception):
    logging.exception(exception)
    response.write(ret_template('500.html').render({}))
    response.set_status(500)        

app = webapp2.WSGIApplication([('/blog', BlogPage),
                               ('/blog'+'.json', BlogPageJsonHandler),
                               ('/search',SearchHandler),
                               ('/',SearchHandler),   
                               ('/share',ShareHandler),                            
                               ('/blog/newpost',FormHandler),
                               ('/blog/(\d+)',ThanksHandler),
                               ('/(\d+)'+'.json',ThanksJsonHandler),
                               ('/signup',SignupHandler),
                               ('/login',LoginHandler),
                               ('/logout',LogoutHandler),
                               ('/welcome',WelcomeHandler),
                               ('/flush',FlushHandler),
                               ('/test',TestHandler),
                               ('/download', DownloadHandler)], debug=True) 

app.error_handlers[404] = handle_404
app.error_handlers[500] = handle_500                                      