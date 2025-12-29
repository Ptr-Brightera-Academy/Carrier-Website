from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, abort, session, flash
from database import get_courses_from_db, get_jobs_from_db, get_job_from_db, add_application_to_db, has_user_already_applied, get_applicants, count_applicants,get_unique_education_levels, get_user_by_email, add_user, get_user_by_username
import os
from werkzeug.utils import secure_filename
from flask import current_app
import uuid
from io import StringIO
import csv
from flask import Response
from database import engine
from sqlalchemy import text
from werkzeug.security import check_password_hash
from flask_login import logout_user, login_required



app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")


UPLOAD_FOLDER = os.path.join('static', 'resumes')
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'
           
@app.route("/")
def home_page():
    courses = get_courses_from_db()
    return render_template('home.html', courses=courses)

@app.route("/course/<string:title>")
def course_details(title):
    courses = get_courses_from_db()
    course = next((c for c in courses if c['title'] == title), None)

    if not course:
        abort(404)

    return render_template('pages/courses/course_details.html', course=course)

@app.route("/enroll/<string:title>")
def enroll(title):
    courses = get_courses_from_db()
    course = next((c for c in courses if c['title'] == title), None)
    if not course:
        abort(404)
    
    return render_template('pages/courses/enroll.html', course=course)

        
@app.route("/careers")
def brightera_careers():
    JOBS = get_jobs_from_db()
    return render_template('pages/careers.html', jobs=JOBS)
    
@app.route("/job/<id>")
def show_job(id):
    job = get_job_from_db(id)
    if not job:
        return "Not Found", 404
    return render_template('pages/jobpage.html', job=job)
           
@app.route("/job/<id>/apply", methods=['POST'])
def apply_to_job(id):
    data = request.form
    job = get_job_from_db(id)
    user_email = data.get('email')
    resume_file = request.files.get('resume')

    # Check duplicate
    if has_user_already_applied(id, user_email):
        return render_template('pages/error.html', message="You have already applied for this job.", job=job)

    # Validate file
    if not resume_file or not allowed_file(resume_file.filename):
        return render_template('pages/error.html', message="Invalid file. Please upload a PDF resume.", job=job)

    # Save securely
    filename = secure_filename(f"{uuid.uuid4().hex}_{resume_file.filename}")
    resume_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    resume_file.save(resume_path)

    # Store relative path in DB
    resume_url = resume_path  # Relative path from /static

    # Prepare data
    application_data = {
        "full_name": data.get("full_name"),
        "email": user_email,
        "linkedin_url": data.get("linkedin_url"),
        "education": data.get("education"),
        "work_experience": data.get("work_experience"),
        "resume_url": resume_url
    }

    add_application_to_db(id, application_data)

    return render_template('pages/application_submitted.html', application=application_data, job=job)
    
@app.route("/contact_us")
def contact_us():
    return render_template('pages/contact_us.html')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # POST
        username = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        if password1 != password2:
            flash("Passwords do not match")
            return render_template("auth/signup.html")

        if get_user_by_username(username):
            flash("Username already taken")
            return render_template("auth/signup.html")

        if get_user_by_email(email):
            flash("Email already registered")
            return render_template("auth/signup.html")

        if add_user(username, email, password1):
            flash("Account created successfully")
            return redirect(url_for("login"))

        flash("Something went wrong")

    return render_template("auth/signup.html")
    
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("users/dashboard.html")


@app.route("/about_us")
def about_us():
    return render_template('pages/about_us.html')

@app.route("/services")
def services():
    return render_template('pages/services.html')

@app.route("/faqs")
def FAQs():
    return render_template('pages/faqs.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, redirect away
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("username_or_email")
        password = request.form.get("password")

        if not identifier or not password:
            flash("All fields are required")
            return render_template("auth/login.html")

        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT * FROM users
                    WHERE email = :identifier OR username = :identifier
                """),
                {"identifier": identifier}
            )
            user = result.first()

        if user and check_password_hash(user._mapping["password"], password):
            session["user_id"] = user._mapping["id"]
            session["username"] = user._mapping["username"]
            flash("Welcome back!")
            return redirect(url_for("dashboard"))

        flash("Invalid username/email or password")

    return render_template("auth/login.html")

# Students Routes
@app.route('/my_courses')
def my_courses():
    return render_template('users/pages/courses.html')

@app.route('/my_lessons')
def lessons():
    return render_template('users/pages/lessons.html')

@app.route('/quizes')
def quizes():
    return render_template('users/pages/quizes.html')

@app.route('/my_certificate(s)')
def certificates():
    return render_template('users/pages/certificates.html')

@app.route('/discussions')
def discussions():
    return render_template('users/pages/discussions.html')

@app.route('/my_profile')
def profile():
    return render_template('users/pages/profile.html')

@app.route('/my_progress')
def progress():
    return render_template('users/pages/progress.html')

@app.route('/settings')
def settings():
    return render_template('users/pages/settings.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/applicants')
def view_applicants():
    JOBS = get_jobs_from_db()
    page = int(request.args.get('page', 1))
    sort = request.args.get('sort', 'newest')
    job_id = request.args.get('job_id')
    education = request.args.get('education')
    keyword = request.args.get('keyword')

    applicants = get_applicants(page, 10, sort, job_id, education, keyword)
    total = count_applicants(job_id, education, keyword)
    total_pages = (total + 9) // 10

    education_options = get_unique_education_levels()

    return render_template(
        'admin/view_applicants.html',
        applicants=applicants,
        page=page,
        total_pages=total_pages,
        sort=sort,
        job_id=job_id,
        jobs=JOBS,
        education=education,
        keyword=keyword,
        education_options=education_options
    )

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)