from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, abort, session, flash, current_app
from database import get_courses_from_db, get_jobs_from_db, get_job_from_db, add_application_to_db, has_user_already_applied, get_applicants, count_applicants,get_unique_education_levels, get_user_by_email, add_user, get_user_by_username, engine, enroll_student, is_user_enrolled, get_enrolled_courses, get_quiz_courses, get_user_progress, save_answers, get_next_questions,require_enrollment, get_user_exams
import os
from werkzeug.utils import secure_filename
import uuid
from sqlalchemy import text
from werkzeug.security import check_password_hash
from flask_login import LoginManager, UserMixin, logout_user, login_required, login_user, current_user
import random
from datetime import datetime


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


@app.route("/auth/login", methods=["GET", "POST"])
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
@app.route("/student/dashboard")
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


@app.route('/student/courses')
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











@app.route('/student/quizes')
@login_required
def quizes():
    courses = get_quiz_courses(current_user.id)
    exams = get_user_exams(current_user.id)
    return render_template(
        'users/pages/quizes.html',
        courses=courses, exams=exams
    )

@app.route("/exam/<exam_slug>/start")
@login_required
def start_exam(exam_slug):
    with engine.connect() as conn:
        # 1️⃣ Get exam by slug
        exam = conn.execute(text("""
            SELECT id, title FROM exams
            WHERE slug = :slug AND is_published = 1
        """), {"slug": exam_slug}).fetchone()

        if not exam:
            flash("Exam not found or not published.", "danger")
            return redirect(url_for("quizes"))

        exam_id = exam.id

        # 2️⃣ Check for any existing attempt
        existing = conn.execute(text("""
            SELECT id, status FROM exam_attempts
            WHERE exam_id = :exam_id
            AND user_id = :user_id
        """), {"exam_id": exam_id, "user_id": current_user.id}).fetchone()

        if existing:
            if existing.status == 'in_progress':
                return redirect(url_for("exam_question", exam_slug=exam_slug))
            else:
                flash("You have already completed this exam.", "info")
                return redirect(url_for("exam_results", exam_slug=exam_slug))

        # 3️⃣ Get question IDs
        questions = conn.execute(text("""
            SELECT id FROM exam_questions
            WHERE exam_id = :exam_id
            ORDER BY position
        """), {"exam_id": exam_id}).fetchall()

        if not questions:
            flash("This exam has no questions yet.", "warning")
            return redirect(url_for("quizes"))

        question_ids = [str(q.id) for q in questions]
        random.shuffle(question_ids)
        order_string = ",".join(question_ids)

        # 4️⃣ Create attempt
        conn.execute(text("""
            INSERT INTO exam_attempts (exam_id, user_id, question_order)
            VALUES (:exam_id, :user_id, :order)
        """), {
            "exam_id": exam_id,
            "user_id": current_user.id,
            "order": order_string
        })

        conn.commit()
        flash("Exam started! Good luck!", "success")

    return redirect(url_for("exam_question", exam_slug=exam_slug))

@app.route("/exam/<exam_slug>/question")
@login_required
def exam_question(exam_slug):
    with engine.connect() as conn:
        # Get active attempt
        attempt = conn.execute(text("""
            SELECT ea.*
            FROM exam_attempts ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.user_id = :user_id
            AND e.slug = :slug
            AND ea.status = 'in_progress'
        """), {"user_id": current_user.id, "slug": exam_slug}).mappings().fetchone()

    if not attempt:
        flash("No active exam session found.", "warning")
        return redirect(url_for("quizes"))

    # Get question order
    if not attempt['question_order']:
        flash("Exam questions not properly configured.", "danger")
        return redirect(url_for("quizes"))

    question_ids = attempt['question_order'].split(",")
    index = attempt['current_question'] - 1

    # Check if exam is complete
    if index >= len(question_ids):
        return redirect(url_for("submit_exam", exam_slug=exam_slug))

    # Get current question
    question_id = question_ids[index]

    with engine.connect() as conn:
        question = conn.execute(text("""
            SELECT * FROM exam_questions
            WHERE id = :id
        """), {"id": question_id}).mappings().fetchone()

    if not question:
        flash("Question not found.", "danger")
        return redirect(url_for("quizes"))

    # Get options for MCQ
    options = []
    if question['question_type'] == 'mcq':
        with engine.connect() as conn:
            options = conn.execute(text("""
                SELECT id, option_text FROM exam_options
                WHERE question_id = :qid
            """), {"qid": question_id}).mappings().all()

    # Get existing answer if any
    with engine.connect() as conn:
        existing_answer = conn.execute(text("""
            SELECT * FROM exam_answers
            WHERE attempt_id = :attempt_id
            AND question_id = :question_id
        """), {
            "attempt_id": attempt['id'],
            "question_id": question_id
        }).mappings().fetchone()

    return render_template("users/pages/exam/question.html",
                           exam_slug=exam_slug,
                           question=question,
                           options=options,
                           existing_answer=existing_answer,
                           question_number=index + 1,
                           total_questions=len(question_ids),
                           attempt=attempt)

@app.route("/exam/<exam_slug>/answer", methods=["POST"])
@login_required
def save_answer(exam_slug):
    # Validate form data
    question_id = request.form.get('question_id')
    answer_text = request.form.get('answer_text', '').strip()
    selected_option = request.form.get('selected_option')

    if not question_id:
        flash("Invalid question.", "danger")
        return redirect(url_for("exam_question", exam_slug=exam_slug))

    with engine.connect() as conn:
        # Get active attempt
        attempt = conn.execute(text("""
            SELECT ea.id
            FROM exam_attempts ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.user_id = :user_id
            AND e.slug = :slug
            AND ea.status = 'in_progress'
        """), {"user_id": current_user.id, "slug": exam_slug}).fetchone()

        if not attempt:
            flash("No active exam session.", "warning")
            return redirect(url_for("quizes"))

        attempt_id = attempt.id

        # Save or update answer
        try:
            selected_option_id = int(selected_option) if selected_option else None
        except (ValueError, TypeError):
            selected_option_id = None

        # Check if answer already exists
        existing = conn.execute(text("""
            SELECT id FROM exam_answers
            WHERE attempt_id = :attempt_id
            AND question_id = :question_id
        """), {
            "attempt_id": attempt_id,
            "question_id": question_id
        }).fetchone()

        if existing:
            # Update existing answer
            conn.execute(text("""
                UPDATE exam_answers
                SET answer_text = :text,
                    selected_option_id = :option,
                    updated_at = NOW()
                WHERE attempt_id = :attempt_id
                AND question_id = :question_id
            """), {
                "attempt_id": attempt_id,
                "question_id": question_id,
                "text": answer_text if answer_text else None,
                "option": selected_option_id
            })
        else:
            # Insert new answer
            conn.execute(text("""
                INSERT INTO exam_answers (attempt_id, question_id, answer_text, selected_option_id)
                VALUES (:attempt_id, :question_id, :text, :option)
            """), {
                "attempt_id": attempt_id,
                "question_id": question_id,
                "text": answer_text if answer_text else None,
                "option": selected_option_id
            })

        # Move to next question
        conn.execute(text("""
            UPDATE exam_attempts
            SET current_question = current_question + 1
            WHERE id = :id
        """), {"id": attempt_id})

        conn.commit()

    return redirect(url_for("exam_question", exam_slug=exam_slug))

@app.route("/exam/<exam_slug>/submit")
@login_required
def submit_exam(exam_slug):
    with engine.connect() as conn:
        # Get active attempt
        attempt = conn.execute(text("""
            SELECT ea.*
            FROM exam_attempts ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.user_id = :user_id
            AND e.slug = :slug
            AND ea.status = 'in_progress'
        """), {"user_id": current_user.id, "slug": exam_slug}).fetchone()

        if not attempt:
            flash("No exam to submit.", "warning")
            return redirect(url_for("quizes"))

        # Calculate auto score for MCQs
        total_marks = 0
        answers = conn.execute(text("""
            SELECT ea.*, eq.question_type, eq.marks, eo.is_correct
            FROM exam_answers ea
            JOIN exam_questions eq ON ea.question_id = eq.id
            LEFT JOIN exam_options eo ON ea.selected_option_id = eo.id
            WHERE ea.attempt_id = :attempt_id
        """), {"attempt_id": attempt.id}).fetchall()

        for answer in answers:
            if answer.question_type == 'mcq' and answer.is_correct:
                total_marks += answer.marks
            elif answer.question_type in ['short', 'long']:
                # For non-MCQ, auto_mark remains 0 (needs manual grading)
                pass

        # Update attempt with auto score
        conn.execute(text("""
            UPDATE exam_attempts
            SET status = 'submitted',
                submitted_at = NOW(),
                auto_score = :score,
                final_score = :score
            WHERE id = :id
        """), {
            "id": attempt.id,
            "score": total_marks
        })

        conn.commit()
        flash("Exam submitted successfully!", "success")

    return redirect(url_for("exam_results", exam_slug=exam_slug))

@app.route("/exam/<exam_slug>/results")
@login_required
def exam_results(exam_slug):
    """Show exam results only if graded"""
    with engine.connect() as conn:
        # Get exam details - ✅ use e.total_marks directly
        exam = conn.execute(text("""
            SELECT e.*, c.title as course_title
            FROM exams e
            JOIN courses c ON e.course_id = c.id
            WHERE e.slug = :slug
        """), {"slug": exam_slug}).mappings().fetchone()

        if not exam:
            abort(404)

        # Get user's attempt
        attempt = conn.execute(text("""
            SELECT * FROM exam_attempts
            WHERE exam_id = :exam_id
            AND user_id = :user_id
            AND status = 'graded'  # Only show if graded
            ORDER BY submitted_at DESC
            LIMIT 1
        """), {
            "exam_id": exam['id'],
            "user_id": current_user.id
        }).mappings().fetchone()

        if not attempt:
            flash("Exam results are not available yet. Please check back later.", "info")
            return redirect(url_for("quizes"))

        # ✅ Use the total_marks column from exams table
        total_marks = exam['total_marks'] or 0
        final_score = attempt['final_score'] or 0

        # Calculate percentage
        percentage = 0
        if total_marks > 0:
            percentage = round((final_score / total_marks) * 100, 1)

        # Get grading log
        grading_log = conn.execute(text("""
            SELECT eg.*, u.username as graded_by_name
            FROM exam_grading_log eg
            LEFT JOIN users u ON eg.graded_by = u.id
            WHERE eg.attempt_id = :attempt_id
            ORDER BY eg.graded_at DESC
            LIMIT 1
        """), {"attempt_id": attempt['id']}).mappings().fetchone()

        # Get answers with detailed information
        answers = conn.execute(text("""
            SELECT 
                ea.*,
                eq.question_text,
                eq.question_type,
                eq.marks,
                eo.option_text as selected_option_text,
                eo.is_correct,
                COALESCE(ea.auto_mark, 0) + COALESCE(ea.manual_mark, 0) as total_mark
            FROM exam_answers ea
            JOIN exam_questions eq ON ea.question_id = eq.id
            LEFT JOIN exam_options eo ON ea.selected_option_id = eo.id
            WHERE ea.attempt_id = :attempt_id
            ORDER BY eq.position
        """), {"attempt_id": attempt['id']}).mappings().all()

        # Calculate performance statistics
        correct_count = 0
        partial_count = 0
        incorrect_count = 0

        for answer in answers:
            total_mark = answer['total_mark'] or 0
            marks = answer['marks'] or 1

            if total_mark >= marks:
                correct_count += 1
            elif total_mark > 0:
                partial_count += 1
            else:
                incorrect_count += 1

    return render_template("exam/results.html",
                           exam=exam,
                           attempt=attempt,
                           answers=answers,
                           grading_log=grading_log,
                           correct_count=correct_count,
                           partial_count=partial_count,
                           incorrect_count=incorrect_count,
                           percentage=percentage)

@app.route("/exam/disqualified")
@login_required
def exam_disqualified():
    return render_template("users/pages/exam/disqualified.html")


@app.route("/exam/violation", methods=["POST"])
@login_required
def record_violation():
    """Record exam violation and disqualify immediately"""
    try:
        data = request.get_json()
        violation_type = data.get('violation_type', 'unknown')

        with engine.connect() as conn:
            # Get the most recent active attempt for this user
            attempt = conn.execute(text("""
                SELECT ea.id, ea.exam_id
                FROM exam_attempts ea
                WHERE ea.user_id = :user_id
                AND ea.status = 'in_progress'
                ORDER BY ea.started_at DESC
                LIMIT 1
            """), {"user_id": current_user.id}).fetchone()

            if attempt:
                # Record violation
                conn.execute(text("""
                    INSERT INTO exam_violations (attempt_id, violation_type)
                    VALUES (:attempt_id, :violation_type)
                """), {
                    "attempt_id": attempt.id,
                    "violation_type": violation_type
                })

                # DISQUALIFY IMMEDIATELY
                conn.execute(text("""
                    UPDATE exam_attempts
                    SET status = 'disqualified',
                        submitted_at = NOW()
                    WHERE id = :id
                """), {"id": attempt.id})

                conn.commit()

        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/exam/<exam_slug>/auto-save", methods=["POST"])
@login_required
def auto_save_answer(exam_slug):
    """Auto-save answer without moving to next question"""
    try:
        question_id = request.form.get('question_id')
        answer_text = request.form.get('answer_text', '').strip()
        selected_option = request.form.get('selected_option')

        with engine.connect() as conn:
            # Get active attempt
            attempt = conn.execute(text("""
                SELECT ea.id
                FROM exam_attempts ea
                JOIN exams e ON ea.exam_id = e.id
                WHERE ea.user_id = :user_id
                AND e.slug = :slug
                AND ea.status = 'in_progress'
            """), {"user_id": current_user.id, "slug": exam_slug}).fetchone()

            if not attempt:
                return jsonify({"success": False, "error": "No active attempt"}), 400

            attempt_id = attempt.id

            # Convert selected_option to integer if it exists
            try:
                selected_option_id = int(selected_option) if selected_option else None
            except (ValueError, TypeError):
                selected_option_id = None

            # Save or update answer
            existing = conn.execute(text("""
                SELECT id FROM exam_answers
                WHERE attempt_id = :attempt_id
                AND question_id = :question_id
            """), {
                "attempt_id": attempt_id,
                "question_id": question_id
            }).fetchone()

            if existing:
                # Update existing answer
                conn.execute(text("""
                    UPDATE exam_answers
                    SET answer_text = :text,
                        selected_option_id = :option,
                        updated_at = NOW()
                    WHERE attempt_id = :attempt_id
                    AND question_id = :question_id
                """), {
                    "attempt_id": attempt_id,
                    "question_id": question_id,
                    "text": answer_text if answer_text else None,
                    "option": selected_option_id
                })
            else:
                # Insert new answer
                conn.execute(text("""
                    INSERT INTO exam_answers (attempt_id, question_id, answer_text, selected_option_id)
                    VALUES (:attempt_id, :question_id, :text, :option)
                """), {
                    "attempt_id": attempt_id,
                    "question_id": question_id,
                    "text": answer_text if answer_text else None,
                    "option": selected_option_id
                })

            conn.commit()

        return jsonify({"success": True, "message": "Answer auto-saved"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/exam/<exam_slug>/timeout", methods=["POST"])
@login_required
def handle_timeout(exam_slug):
    """Handle when time runs out for a question"""
    try:
        question_id = request.form.get('question_id')

        with engine.connect() as conn:
            # Get active attempt
            attempt = conn.execute(text("""
                SELECT ea.id
                FROM exam_attempts ea
                JOIN exams e ON ea.exam_id = e.id
                WHERE ea.user_id = :user_id
                AND e.slug = :slug
                AND ea.status = 'in_progress'
            """), {"user_id": current_user.id, "slug": exam_slug}).fetchone()

            if not attempt:
                return jsonify({"success": False, "error": "No active attempt"}), 400

            attempt_id = attempt.id

            # Save empty answer (time ran out)
            conn.execute(text("""
                INSERT INTO exam_answers (attempt_id, question_id, time_taken_seconds)
                VALUES (:attempt_id, :question_id, 0)
                ON DUPLICATE KEY UPDATE
                    time_taken_seconds = 0
            """), {
                "attempt_id": attempt_id,
                "question_id": question_id
            })

            # Move to next question
            conn.execute(text("""
                UPDATE exam_attempts
                SET current_question = current_question + 1
                WHERE id = :id
            """), {"id": attempt_id})

            conn.commit()

        return jsonify({"success": True, "redirect": url_for('exam_question', exam_slug=exam_slug)}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500





















    
@app.route("/quiz/<course_slug>/start")
@login_required
def start_quiz(course_slug):

    with engine.connect() as conn:

        course = conn.execute(
            text("SELECT * FROM courses WHERE slug=:slug"),
            {"slug": course_slug}
        ).first()

        quiz = conn.execute(
            text("SELECT * FROM quizzes WHERE course_id=:cid"),
            {"cid": course.id}
        ).first()

        # 🔑 ALWAYS create a new attempt
        conn.execute(text("""
            INSERT INTO quiz_attempts (user_id, quiz_id, completed)
            VALUES (:uid, :qid, 0)
        """), {
            "uid": current_user.id,
            "qid": quiz.id
        })

        conn.commit()

    return redirect(url_for("quiz_questions", course_slug=course_slug))

@app.route("/courses/<slug>/error")
@login_required
def course_access_error(slug):

    with engine.connect() as conn:

        course = conn.execute(
            text("SELECT * FROM courses WHERE slug = :slug"),
            {"slug": slug}
        ).first()

        if not course:
            abort(404)

    return render_template(
        "users/pages/error.html",
        title="Course Not Enrolled", course=course,
        message="You are not enrolled in this course. Enroll to unlock lessons and quizzes."), 403



@app.route("/quiz/<course_slug>/questions")
@login_required
def quiz_questions(course_slug):

    offset = int(request.args.get("offset", 0))

    with engine.connect() as conn:

        # 1. Get course
        course = conn.execute(
            text("SELECT * FROM courses WHERE slug = :slug"),
            {"slug": course_slug}
        ).first()

        if not course:
            abort(403)

        # 2. 🔒 Enrollment check (VERY IMPORTANT)
        if not require_enrollment(current_user.id, course.id, conn):
            return redirect(
                url_for("course_access_error", slug=course.slug, not_enrolled=1)
            )

        # 3. Get quiz
        quiz = conn.execute(
            text("SELECT * FROM quizzes WHERE course_id = :cid"),
            {"cid": course.id}
        ).first()

        if not quiz:
            abort(404)

        # 4. Get questions
        questions = conn.execute(text("""
            SELECT * FROM quiz_questions
            WHERE quiz_id = :qid
            ORDER BY id
            LIMIT 3 OFFSET :off
        """), {
            "qid": quiz.id,
            "off": offset
        }).fetchall()

        # 5. If no questions left → results
        if not questions:
            return redirect(
                url_for("quiz_result", course_slug=course.slug)
            )

        # 6. Get options safely
        question_ids = [q.id for q in questions]

        options = conn.execute(
            text("""
                SELECT * FROM quiz_options
                WHERE question_id IN :ids
            """).bindparams(
                ids=tuple(question_ids)
            )
        ).fetchall()

    return render_template(
        "users/pages/quiz_page.html",
        course=course,
        quiz=quiz,
        questions=questions,
        options=options,
        offset=offset
    )



@app.route("/quiz/<course_slug>/submit", methods=["POST"])
@login_required
def submit_quiz(course_slug):

    offset = int(request.form.get("offset", 0))

    with engine.connect() as conn:

        quiz = conn.execute(text("""
            SELECT q.*
            FROM quizzes q
            JOIN courses c ON q.course_id=c.id
            WHERE c.slug=:slug
        """), {"slug": course_slug}).first()

        attempt = conn.execute(text("""
            SELECT * FROM quiz_attempts
            WHERE user_id=:uid AND quiz_id=:qid AND completed=0
            ORDER BY id DESC
            LIMIT 1
        """), {
            "uid": current_user.id,
            "qid": quiz.id
        }).first()

        for key, value in request.form.items():
            if not key.startswith("q"):
                continue

            qid = int(key.replace("q", ""))

            correct_option = conn.execute(
                text("SELECT correct_option FROM quiz_questions WHERE id=:id"),
                {"id": qid}
            ).scalar()

            conn.execute(text("""
                INSERT INTO quiz_answers
                (attempt_id, question_id, selected_option, is_correct)
                VALUES (:aid, :qid, :sel, :ok)
            """), {
                "aid": attempt.id,
                "qid": qid,
                "sel": value,
                "ok": value == correct_option
            })

        conn.commit()

    return redirect(
        url_for("quiz_questions", course_slug=course_slug, offset=offset + 3)
    )


@app.route("/quiz/<course_slug>/result")
@login_required
def quiz_result(course_slug):

    with engine.connect() as conn:

        course = conn.execute(
            text("SELECT * FROM courses WHERE slug=:slug"),
            {"slug": course_slug}
        ).first()

        quiz = conn.execute(
            text("SELECT * FROM quizzes WHERE course_id=:cid"),
            {"cid": course.id}
        ).first()

        attempt = conn.execute(text("""
            SELECT * FROM quiz_attempts
            WHERE user_id=:uid AND quiz_id=:qid
            ORDER BY id DESC
            LIMIT 1
        """), {
            "uid": current_user.id,
            "qid": quiz.id
        }).first()

        total_questions = quiz.total_questions

        # ✅ CORRECT answers (THIS attempt only)
        correct = conn.execute(text("""
            SELECT COUNT(*)
            FROM quiz_answers
            WHERE attempt_id=:aid AND is_correct=1
        """), {"aid": attempt.id}).scalar()

        wrong = total_questions - correct
        percentage = round((correct / total_questions) * 100, 2)

        # ✅ FAILED questions (NO duplicates)
        failed = conn.execute(text("""
            SELECT DISTINCT qq.id
            FROM quiz_answers qa
            JOIN quiz_questions qq ON qa.question_id = qq.id
            WHERE qa.attempt_id=:aid AND qa.is_correct=0
            ORDER BY qq.id
        """), {"aid": attempt.id}).fetchall()

        failed_numbers = [q.id for q in failed]

        # ✅ UPDATE attempt ONCE
        if attempt.completed == 0:
            conn.execute(text("""
                UPDATE quiz_attempts
                SET score=:score,
                    percentage=:percentage,
                    completed=1,
                    completed_at=CURRENT_TIMESTAMP
                WHERE id=:aid
            """), {
                "score": correct,
                "percentage": percentage,
                "aid": attempt.id
            })

            conn.commit()

    return render_template(
        "users/pages/quiz_result.html",
        course=course,
        quiz=quiz,
        total_questions=total_questions,
        correct=correct,
        wrong=wrong,
        percentage=percentage,
        failed_numbers=failed_numbers
    )


@app.route('/student/certificate(s)')
@login_required
def certificates():
    return render_template('users/pages/certificates.html')

@app.route('/student/discussions')
@login_required
def discussions():
    return render_template('users/pages/discussions.html')

@app.route('/student/account/billing')
@login_required
def billing():
    return render_template('users/pages/billing.html')

@app.route('/student/profile')
@login_required
def profile():
    return render_template('users/pages/profile.html', user=current_user)

@app.route('/student/progress')
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



@app.route('/student/completed/lesson', methods=['POST'])
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

@app.route('/student/settings')
@login_required
def settings():
    return render_template('users/pages/settings.html')

@app.route('/student/change-password', methods=['POST'])
@login_required
def change_password():
    # Add password validation & hashing later
    flash("Password updated successfully", "success")
    return redirect(url_for('settings'))


@app.route('/student/logout-all', methods=['POST'])
@login_required
def logout_all_sessions():
    flash("Logged out from all devices.", "success")
    return redirect(url_for('settings'))


@app.route('/student/delete-account', methods=['POST'])
@login_required
def delete_account():
    if request.form.get("confirm_text") == "DELETE":
        # delete user logic here
        flash("Account deleted.", "danger")
    return redirect(url_for('settings'))


@app.route('/student/support/contact', methods=['POST'])
@login_required
def contact_support():
    flash("Support message sent.", "success")
    return redirect(url_for('settings'))


@app.route('/student/support/report', methods=['POST'])
@login_required
def report_problem():
    flash("Problem report submitted.", "warning")
    return redirect(url_for('settings'))


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
# EXAM ROUTES
# ---------------------------




# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
