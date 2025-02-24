from flask import Flask,render_template,request,redirect,url_for,session,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta,datetime

from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import os

app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"
app.config["SECRET_KEY"]="main"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16 MB



app.permanent_session_lifetime=timedelta(days=30)

db=SQLAlchemy(app)

class Main(db.Model):
    __tablename__="main"
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100))
    email=db.Column(db.String(100))
    password_hash=db.Column(db.String(200))
    gender=db.Column(db.String(100))
    def generate_password(self,simple_password):   #generating hashed password
        self.password_hash=generate_password_hash(simple_password)

    def check_password(self,simple_password):   #//checking  hashed with simple password
        return check_password_hash(self.password_hash,simple_password)  



class Teacher(db.Model):
    __tablename__ = "teacher"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('main.id'), nullable=False)
    # email=db.Column(db.String,db.ForeignKey('main.id'),nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    gender=db.Column(db.string(100))
    user = db.relationship('Main', backref=db.backref('teacher', uselist=False))    #whts this



class UploadedFile(db.Model):
    __tablename__="file"
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)  # Stores the file as binary data
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)



class FormData(db.Model):
    __tablename__="form"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)




# class Answer(db.Model):
#      id = db.Column(db.Integer, primary_key=True)
#      ans=db.Column(db.Text(300),nullable=False)
#      question_id=db.Column(db.Integer,db.ForeignKey('form.id'),nullable=False)
#      que = db.relationship('FormData', backref=db.backref('Answer', uselist=False))



# -------------teacher side submit answer
@app.route('/submit_answer', methods=['POST'])
def submit_answer():
        answer_text = request.form.get('answer')
        question_id = request.form.get('question_id')
    
        # Create an Answer object
        # new_answer = Answer(ans=answer_text, question_id=question_id)

        # Add the new answer to the session and commit to the database
        # db.session.add(new_answer)
        db.session.commit()
        flash('Answer submitted successfully!', 'success')
        return redirect(url_for('solve'))


# -------------teacher side solve question route
@app.route("/solve")
def solve():
    doubt_data = FormData.query.all()
    if doubt_data is None:
        return render_template("errorspage/404.html"), 404
    return render_template("solve.html",doubt=doubt_data)


# -----------file upload action
@app.route("/upload", methods=["POST", "GET"])
def upload():
    if request.method == "POST":
        # Get the uploaded file from the form
        file = request.files.get("file")

        # Check if a file was uploaded and validate it
        if file:
            # Secure the filename to prevent directory traversal
            filename = secure_filename(file.filename)

            # Get the file's MIME type (like image/jpeg, text/plain, etc.)
            filetype = file.mimetype

            # Read the file's data as binary
            file_data = file.read()

            # Create an instance of UploadedFile
            uploaded_file = UploadedFile(
                filename=filename,
                filetype=filetype,
                data=file_data,
                upload_date=datetime.utcnow()
            )

            # Save the file to the database
            db.session.add(uploaded_file)
            db.session.commit()

            flash("File uploaded successfully!", "success")
            return redirect(url_for("upload"))  # Redirect to the same page to refresh

        else:
            flash("No file selected or invalid file format.", "danger")

    return redirect(url_for("teacher"))  # Adjust this with your correct template




# -------------signup action route
@app.route("/signup",methods=["POST","GET"])
def sign_up():
    if request.method=="POST":
        username=request.form.get("username")
        email=request.form.get("email")
        password=request.form.get("password")
        gender=request.form.get("gender")
        if Main.query.filter_by(email=email).first():   
            flash("Email already registered ,Log in or use another email","info")
            return redirect(url_for("sign_up"))
        user_object=Main(username=username,email=email,gender=gender)
        user_object.generate_password(password)   #// This will Generate secret$%@#&......... something like this
        db.session.add(user_object)
        db.session.commit()
        

        flash("registered sucessfully! Now you can Log in","info")
        return redirect(url_for("log_in"))
    return render_template("signup.html")



# ---------------login action route
@app.route("/login", methods=["POST", "GET"])
def log_in():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user_object = Main.query.filter_by(email=email).first()

        if user_object and user_object.check_password(password):
            session["user-key"] = email
            session["user-name"] = user_object.username
            session.permanent = True

            # Check if the user is a teacher and store in session
            teacher = Teacher.query.filter_by(user_id=user_object.id).first()
            if teacher:
                session["user-role"] = "teacher"  # Store user role
                flash(f"{user_object.username} logged in as Teacher!", "success")
                return redirect(url_for("teacherhome"))  # Redirect to teacher's page
            else:
                session["user-role"] = "student"  # Store as student
                flash(f"{user_object.username} logged in as Student!", "success")
                return redirect(url_for("home"))  # Redirect to student's home page
        else:
            flash("Invalid email or password. Please try again.", "danger")
            return redirect(url_for("log_in"))
    return render_template("login.html")



# -------------teacher sign up authetication
@app.route("/teacher", methods=["POST", "GET"])
def teacher():    
    if request.method == "POST":
        username = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        subject = request.form.get("subject")
        experience = request.form.get("experience")
        qualification = request.form.get("qualification")
        gender=request.form.get("gender")
        # Check if user already exists
        if Main.query.filter_by(email=email).first():
            flash("This email already exists. Log in to your Teacher account.", "info")
            return redirect(url_for("log_in"))

        # Create new user in Main table
        user_object = Main(username=username, email=email,gender=gender)
        user_object.generate_password(password)  # Hash the password
        db.session.add(user_object)
        db.session.commit()

        # Create teacher details in Teacher table (linked to Main user)
        teacher_object = Teacher(user_id=user_object.id,username=username, subject=subject, experience=experience, qualification=qualification)
        db.session.add(teacher_object)
        db.session.commit()

        flash(f"{username} registered successfully as Teacher!", "success")
        return redirect(url_for("log_in"))

    # Render the teacher home page when method is GET
    return redirect(url_for("started"))



# create databse table if not exists
with app.app_context():
    db.create_all()     


# -------------base.html

@app.route("/base")
def base():
    if "user-key" not in session:
        flash("You need to log in first.", "info")
        return redirect(url_for("log_in"))

    # Get the logged-in user
    user_object = Main.query.filter_by(email=session["user-key"]).first()
    print(user_object)
    
    if user_object:
        return render_template("base.html", user=user_object,gender=user_object.gender)
    
    flash("User not found.", "danger")
    return redirect(url_for("log_in"))



#------home page
@app.route("/")
def home():
    if "user-role" in session:
        if session["user-role"] == "teacher":
            return redirect(url_for("teacherhome"))
    return render_template("home.html")


#------sign_up page
# @app.route("/signup")
# def sign_up():
#     return render_template("signup.html")

# -----------aws page
@app.route("/aws")
def aws():
    return render_template("aws.html")

#-------log_in page
# @app.route("/login")
# def log_in():
#    return render_template("login.html")

#------plan and pricing
@app.route("/plans")
def plans():
    return render_template("/pricing.html")


#-------business page
@app.route("/business")
def business():
    return render_template("/business.html")

#-------teach on our platform page
@app.route("/teach")
def teach():
    # print(session)
    if "user-key" in session:
      return render_template("teach.html")
    else:
      return redirect(url_for('log_in'))



# ----------teacher home page
@app.route("/teacher_home")
def teacherhome():
   return render_template("home_teacher.html")


# -------get started  button pricing
@app.route("/started")
def started():
        return render_template("teacher.html")
    
    


#-------dropdownmenu: certificate
@app.route("/certificate")
def certificate():
      return render_template("certificate.html")
  

# --------home page trial button
@app.route("/trial")
def subscribe():
    if "user-key" in session:
      return redirect(url_for('plans'))
    else:
        return redirect(url_for('log_in'))



# ------log out route
@app.route("/logout")
def logout():
    user_role=session.get("user-role")
    session.pop("user-key", None)
    # session.pop("user-name", None)
    session.pop("user-role", None)  # Clear user role from session
    flash("You have been logged out.", "info")

    if user_role=="teacher":
        return redirect(url_for("teacherhome"))  # Redirect to home page after logout
    else:
        return redirect(url_for("home"))



# ------------doubt form with session 
@app.route("/doubt")
def doubt():
    if 'user-key' not in session:
        return redirect(url_for('log_in'))  # Redirect if not logged in
    return render_template('doubt.html', user=session['user-key'])



# ------------submit action of doubt form
@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message-text']
        
        # Save data to the database
        new_entry = FormData(name=name, email=email, subject=subject, message=message)
        db.session.add(new_entry)
        db.session.commit()

        # Redirect to the home page after submission
        return redirect(url_for('doubt'))



# --------profile page
@app.route('/profile')
def profile():
    if 'user-key' not in session:  # Ensure user is logged in
        return redirect(url_for('log_in'))
    
    user_object = Main.query.filter_by(email=session["user-key"]).first() # Get the logged-in user

    return render_template('profile.html', user=user_object)  # Pass user details to template



# -------error handling

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errorspages/404.html', code=404, message="Oops! The page you're looking for doesn't exist."), 404


@app.errorhandler(500)
def error_500(e):
     return render_template('errorspages/500.html', code=404, message="Oops ! Sorry there is some server error."), 500

if __name__=="__main__":
    app.run(debug=True)