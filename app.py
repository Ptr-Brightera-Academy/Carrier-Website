from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, abort, session, flash, current_app
from database import get_courses_from_db, get_jobs_from_db, get_job_from_db, add_application_to_db, has_user_already_applied, get_applicants, count_applicants,get_unique_education_levels, get_user_by_email, add_user, get_user_by_username, engine, enroll_student
import os
from werkzeug.utils import secure_filename
import uuid
from sqlalchemy import text
from werkzeug.security import check_password_hash
from flask_login import LoginManager, UserMixin, logout_user, login_required, login_user, current_user

# ---------------------------
# APP SETUP
# ---------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")

# ---------------------------
# FLASK-LOGIN SETUP
# ---------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore[assignment]

# ---------------------------
# FILE UPLOAD CONFIG
# ---------------------------
UPLOAD_FOLDER = os.path.join('static', 'resumes')
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------------
# USER MODEL
# ---------------------------
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# ---------------------------
# USER LOADER
# ---------------------------
@login_manager.user_loader
def load_user(user_id):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
        user = result.first()
    if user:
        return User(user._mapping["id"], user._mapping["username"], user._mapping["email"])
    return None

# ---------------------------
# PUBLIC ROUTES
# ---------------------------
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

@app.route("/enroll/<string:title>", methods=["GET", "POST"])
@login_required
def enroll(title):
    # Get course by title
    courses = get_courses_from_db()
    course = next((c for c in courses if c['title'] == title), None)
    if not course:
        abort(404)

    if request.method == "POST":
        user_id = current_user.id
        success = enroll_student(course['id'], user_id)

        if success:
            flash(f"You have successfully enrolled in {course['title']}!", "success")
        else:
            flash("You are already enrolled in this course.", "warning")

        return redirect(url_for("dashboard"))

    # GET request → show confirmation page
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

# ---------------------------
# JOB APPLICATION
# ---------------------------
@app.route("/job/<id>/apply", methods=['POST'])
def apply_to_job(id):
    data = request.form
    job = get_job_from_db(id)
    user_email = data.get('email')
    resume_file = request.files.get('resume')

    if has_user_already_applied(id, user_email):
        return render_template('pages/error.html', message="You have already applied for this job.", job=job)

    if not resume_file or not allowed_file(resume_file.filename):
        return render_template('pages/error.html', message="Invalid file. Please upload a PDF resume.", job=job)

    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    filename = secure_filename(f"{uuid.uuid4().hex}_{resume_file.filename}")
    resume_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    resume_file.save(resume_path)

    application_data = {
        "full_name": data.get("full_name"),
        "email": user_email,
        "linkedin_url": data.get("linkedin_url"),
        "education": data.get("education"),
        "work_experience": data.get("work_experience"),
        "resume_url": resume_path
    }

    add_application_to_db(id, application_data)

    return render_template('pages/application_submitted.html', application=application_data, job=job)

# ---------------------------
# AUTH ROUTES
# ---------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        errors = {}

        # Collect all errors
        if password1 != password2:
            errors['password2'] = "Passwords do not match"

        if get_user_by_username(username):
            errors['username'] = "Username already taken"

        if get_user_by_email(email):
            errors['email'] = "Email already registered"

        # If any errors, render template with errors
        if errors:
            return render_template(
                "auth/signup.html",
                errors=errors,
                username=username,
                email=email
            )

        # If no errors, add user
        if add_user(username, email, password1):
            flash("Account created successfully")
            return redirect(url_for("login"))

        flash("Something went wrong")

    # GET request or no POST
    return render_template("auth/signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("username_or_email")
        password = request.form.get("password")

        if not identifier or not password:
            flash("All fields are required")
            return render_template("auth/login.html")

        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT * FROM users
                WHERE email = :identifier OR username = :identifier
            """), {"identifier": identifier})
            user = result.first()

        if user and check_password_hash(user._mapping["password"], password):
            user_obj = User(user._mapping["id"], user._mapping["username"], user._mapping["email"])
            login_user(user_obj)
            return redirect(url_for("dashboard"))

        flash("Invalid username/email or password")
    return render_template("auth/login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('login'))

# ---------------------------
# DASHBOARD & USER ROUTES
# ---------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("users/dashboard.html")

@app.route('/my_courses')
@login_required
def my_courses():
    return render_template('users/pages/courses.html')

@app.route('/my_lessons')
@login_required
def lessons():
    # Fetch lessons from the database
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT * FROM course_lessons
            ORDER BY lesson_order ASC
        """))
        lessons = result.fetchall()

    # Pass lessons to the template
    return render_template('users/pages/lessons.html', lessons=lessons)

@app.route('/quizes')
@login_required
def quizes():
    return render_template('users/pages/quizes.html')

@app.route('/my_certificate(s)')
@login_required
def certificates():
    return render_template('users/pages/certificates.html')

@app.route('/discussions')
@login_required
def discussions():
    return render_template('users/pages/discussions.html')

@app.route('/my_profile')
@login_required
def profile():
    return render_template('users/pages/profile.html')

@app.route('/my_progress')
@login_required
def progress():
    return render_template('users/pages/progress.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('users/pages/settings.html')

@app.route("/services")
def services():
    return render_template('pages/services.html')

@app.route("/about_us")
def about_us():
    return render_template('pages/about_us.html')

@app.route("/faqs")
def FAQs():
    return render_template('pages/faqs.html')

@app.route("/contact_us") 
def contact_us(): 
    return render_template('pages/contact_us.html')

# ---------------------------
# ADMIN ROUTES
# ---------------------------
@app.route('/applicants')
@login_required
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

# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
