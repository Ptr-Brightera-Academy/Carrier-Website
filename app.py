from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for
from database import get_courses_from_db, get_jobs_from_db, get_job_from_db, add_application_to_db, has_user_already_applied, get_applicants, count_applicants,get_unique_education_levels
import os
from werkzeug.utils import secure_filename
from flask import current_app
import uuid
from io import StringIO
import csv
from flask import Response

app = Flask(__name__)

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

@app.route("/signup")
def signup():
    return render_template('auth/signup.html')

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
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email")
        password = request.form.get("password")

        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT * FROM users 
                WHERE email = :identifier OR username = :identifier
            """), {"identifier": username_or_email})
            user = result.fetchone()

        if user and check_password_hash(user.password, password):
            user_obj = User(id=user.id, username=user.username, email=user.email)
            login_user(user_obj)
            return redirect(url_for("dashboard"))  # Or your landing page
        else:
            flash("Invalid credentials", "danger")

    return render_template("auth/login.html")

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