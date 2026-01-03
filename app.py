from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, abort, session, flash, current_app
from database import get_courses_from_db, get_jobs_from_db, get_job_from_db, add_application_to_db, has_user_already_applied, get_applicants, count_applicants,get_unique_education_levels, get_user_by_email, add_user, get_user_by_username, engine, enroll_student, is_user_enrolled, get_enrolled_courses, get_quiz_courses, get_user_progress, save_answers, get_next_questions
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

@app.route("/enroll/<string:title>")
def enroll(title):
    courses = get_courses_from_db()

    course = next((c for c in courses if c['title'] == title), None)

    if not course:
        abort(404)

    return render_template('pages/courses/enroll.html', course=course)

@app.route("/confirm/enroll/<string:title>")
@login_required
def confirm_enroll(title):
    courses = get_courses_from_db()
    course = next((c for c in courses if c['title'] == title), None)

    if not course:
        abort(404)

    user_id = current_user.id
    success = enroll_student(course['id'], user_id)

    if success:
        flash(f"You have successfully enrolled in {course['title']}!", "success")
    else:
        flash("You are already enrolled in this course.", "warning")

    return redirect(url_for("already_enrolled", title=title))


@app.route("/enrolled/<string:title>")
def already_enrolled(title):
    # Get the course
    courses = get_courses_from_db() 
    course = next((c for c in courses if c['title'] == title), None)
    if not course:
        abort(404)

    # Get current user
    user_id = session.get("user_id")
    if not user_id:
        # Optionally redirect to login if no user
        return redirect(url_for("login"))

    # Check if user is already enrolled
    if not is_user_enrolled(user_id, course['id']):
        # If not enrolled, maybe redirect to enrollment page
        return redirect(url_for("enroll", title=title))

    # Render page saying user is already enrolled
    return render_template('pages/courses/already_enrolled.html', course=course)



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
            user_obj = User(
                user._mapping["id"],
                user._mapping["username"],
                user._mapping["email"]
            )

            login_user(user_obj)

            # 👇 THIS IS THE FIX
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))

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
    user = current_user

    # Get courses and progress for this user
    courses_progress = get_user_progress(user.id)

    total_courses = len(courses_progress)
    total_lessons_completed = sum(c['completed_lessons'] for c in courses_progress)
    total_lessons = sum(c['total_lessons'] for c in courses_progress)
    total_certificates = 0  # You can update this if you track certificates in another table

    return render_template(
        "users/dashboard.html",
        user=user,
        courses_progress=courses_progress,
        total_courses=total_courses,
        total_lessons_completed=total_lessons_completed,
        total_lessons=total_lessons,
        total_certificates=total_certificates
    )


@app.route('/my_courses')
@login_required
def my_courses():
    courses = get_enrolled_courses(current_user.id)
    return render_template('users/pages/courses.html',courses=courses)


@app.route('/lessons/<course_slug>/<lesson_slug>')
@login_required
def lesson_page(course_slug, lesson_slug):

    with engine.connect() as conn:

        # Get course
        course = conn.execute(
            text("SELECT * FROM courses WHERE slug = :slug"),
            {"slug": course_slug}
        ).first()

        if not course:
            abort(404)

        # Get ALL lessons (for sidebar)
        lessons = conn.execute(
            text("""
                SELECT *
                FROM course_lessons
                WHERE course_id = :course_id
                ORDER BY lesson_order ASC
            """),
            {"course_id": course._mapping["id"]}
        ).fetchall()

        # Get CURRENT lesson
        lesson = conn.execute(
            text("""
                SELECT *
                FROM course_lessons
                WHERE slug = :slug AND course_id = :course_id
            """),
            {
                "slug": lesson_slug,
                "course_id": course._mapping["id"]
            }
        ).first()

        if not lesson:
            abort(404)

    # Find previous & next lesson
    lesson_ids = [l._mapping["id"] for l in lessons]
    index = lesson_ids.index(lesson._mapping["id"])

    prev_lesson = lessons[index - 1] if index > 0 else None
    next_lesson = lessons[index + 1] if index < len(lessons) - 1 else None

    return render_template(
        "users/pages/lessons.html",
        course=course,
        lessons=lessons,     
        lesson=lesson,
        prev_lesson=prev_lesson,
        next_lesson=next_lesson
    )

@app.route('/lessons/<course_slug>')
@login_required
def lessons(course_slug):
    with engine.connect() as conn:
        course = conn.execute(
            text("SELECT * FROM courses WHERE slug = :slug"),
            {"slug": course_slug}
        ).first()

        if not course:
            abort(404)

        first_lesson = conn.execute(
            text("""
                SELECT slug
                FROM course_lessons
                WHERE course_id = :course_id
                ORDER BY lesson_order ASC
                LIMIT 1
            """),
            {"course_id": course._mapping["id"]}
        ).first()

    if not first_lesson:
        return render_template(
            "users/pages/no_lessons.html",
            course=course
        )

    return redirect(
        url_for(
            "lesson_page",
            course_slug=course.slug,
            lesson_slug=first_lesson.slug
        )
    )

@app.route('/quizes')
@login_required
def quizes():
    courses = get_quiz_courses(current_user.id)
    return render_template(
        'users/pages/quizes.html',
        courses=courses
    )
    


@app.route("/quiz/<course_slug>/start", methods=["GET", "POST"])
@login_required
def start_quiz(course_slug):

    # Which page of questions are we on?
    offset = int(
        request.form.get("offset")
        or request.args.get("offset", 0)
    )


    with engine.connect() as conn:

        # 1. Load course
        course = conn.execute(
            text("SELECT * FROM courses WHERE slug=:slug"),
            {"slug": course_slug}
        ).first()

        if not course:
            abort(404)

        # 2. Load quiz
        quiz = conn.execute(
            text("SELECT * FROM quizzes WHERE course_id=:cid"),
            {"cid": course.id}
        ).first()

        if not quiz:
            abort(404)

        # 4. Load next 3 questions
        questions = conn.execute(
            text("""
                SELECT * FROM quiz_questions
                WHERE quiz_id=:qid
                ORDER BY id ASC
                LIMIT 3 OFFSET :off
            """),
            {"qid": quiz.id, "off": offset}
        ).fetchall()

        # If no more questions → go to results
        if not questions:
            return redirect(url_for("quiz_result", course_slug=course.slug))

        # 5. Load options
        ids = [q.id for q in questions]
        placeholders = ",".join(str(i) for i in ids)

        options = conn.execute(
            text(f"""
                SELECT * FROM quiz_options
                WHERE question_id IN ({placeholders})
            """)
        ).fetchall()

    next_offset = offset + 3

    return render_template(
        "users/pages/quiz_page.html",
        course=course,
        quiz=quiz,
        questions=questions,
        options=options,
        offset=next_offset
    )

@app.route("/quiz/<course_slug>/submit", methods=["POST"])
@login_required
def submit_quiz(course_slug):

    with engine.connect() as conn:
        quiz = conn.execute(
            text("""
                SELECT q.*
                FROM quizzes q
                JOIN courses c ON q.course_id=c.id
                WHERE c.slug=:slug
            """),
            {"slug": course_slug}
        ).first()

    save_answers(request.form, current_user.id, quiz.id)

    return redirect(url_for("start_quiz", course_slug=course_slug))


@app.route("/quiz/<course_slug>/result")
@login_required
def quiz_result(course_slug):

    with engine.connect() as conn:

        # 1. Load course
        course = conn.execute(
            text("SELECT * FROM courses WHERE slug=:slug"),
            {"slug": course_slug}
        ).first()

        if not course:
            abort(404)

        # 2. Load quiz
        quiz = conn.execute(
            text("SELECT * FROM quizzes WHERE course_id=:cid"),
            {"cid": course.id}
        ).first()

        if not quiz:
            abort(404)

        # 3. Get active attempt
        attempt = conn.execute(
            text("""
                SELECT * FROM quiz_attempts
                WHERE user_id=:uid
                AND quiz_id=:qid
                AND completed=0
            """),
            {
                "uid": current_user.id,
                "qid": quiz.id
            }
        ).first()

        if not attempt:
            # No active attempt → redirect somewhere safe
            return redirect(url_for("quizes"))

        # 4. Calculate stats
        total_questions = conn.execute(
            text("""
                SELECT COUNT(*) FROM quiz_questions
                WHERE quiz_id=:qid
            """),
            {"qid": quiz.id}
        ).scalar()

        answered = conn.execute(
            text("""
                SELECT COUNT(*) FROM quiz_answers
                WHERE attempt_id=:aid
            """),
            {"aid": attempt.id}
        ).scalar()

        correct = conn.execute(
            text("""
                SELECT COUNT(*) FROM quiz_answers
                WHERE attempt_id=:aid AND is_correct=1
            """),
            {"aid": attempt.id}
        ).scalar()

        wrong = answered - correct
        score = round((correct / total_questions) * 100, 2) if total_questions else 0

        # 5. Mark attempt as completed
        conn.execute(
            text("""
                UPDATE quiz_attempts
                SET completed=1
                WHERE id=:aid
            """),
            {"aid": attempt.id}
        )

        conn.commit()

    return render_template(
        "users/pages/quiz_result.html",
        course=course,
        quiz=quiz,
        total_questions=total_questions,
        answered=answered,
        correct=correct,
        wrong=wrong,
        score=score
    )






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
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT 
                c.title,
                COUNT(lp.lesson_id) AS completed,
                (SELECT COUNT(*) FROM course_lessons WHERE course_id = c.id) AS total
            FROM courses c
            JOIN enrollments e ON e.course_id = c.id
            LEFT JOIN lesson_progress lp 
              ON lp.course_id = c.id 
              AND lp.user_id = :user_id 
              AND lp.completed = 1
            WHERE e.user_id = :user_id
            GROUP BY c.id
        """), {"user_id": current_user.id}).fetchall()

    return render_template("users/pages/progress.html", rows=rows)



@app.route('/complete_lesson', methods=['POST'])
@login_required
def complete_lesson():
    data = request.get_json()
    lesson_id = data['lesson_id']
    course_id = data['course_id']

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO lesson_progress (user_id, course_id, lesson_id, completed, completed_at)
            VALUES (:user_id, :course_id, :lesson_id, 1, NOW())
            ON DUPLICATE KEY UPDATE completed = 1, completed_at = NOW()
        """), {
            "user_id": current_user.id,
            "course_id": course_id,
            "lesson_id": lesson_id
        })

    return {"status": "ok"}





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
