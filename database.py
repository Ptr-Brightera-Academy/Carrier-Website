import os
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash, check_password_hash



cert_path = os.path.join(os.path.dirname(__file__), 'certs', 'isrgrootx1.pem')

ssl_args = {
    "ssl": {
        "ca": cert_path
    }
}
my_secret = os.environ['DB_CONNECTION_STRING']
engine = create_engine(
  my_secret,
    connect_args=ssl_args,
    echo=True
)

def get_jobs_from_db():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM jobs"))
        jobs = []
        for row in result.all():
            jobs.append(dict(row._mapping))
        return(jobs)

def get_courses_from_db():
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT 
                courses.*, 
                users.username AS instructor_username
            FROM 
                courses
            LEFT JOIN 
                users ON courses.instructor_id = users.id
        """))

        courses = []
        for row in result.all():
            courses.append(dict(row._mapping))

        return courses

def get_job_from_db(id):
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM jobs WHERE id = :val"), {"val": id})
        rows = result.all()
        if len(rows) == 0:
            return None
        else:
          return dict(rows[0]._mapping)  

def has_user_already_applied(job_id, email):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT 1 FROM applications WHERE job_id = :job_id AND email = :email"),
            {"job_id": job_id, "email": email}
        )
        return result.first() is not None


def add_application_to_db(job_id, data):
            with engine.begin() as conn:
                query = text("""
                    INSERT INTO applications (
                        job_id, full_name, email, linkedin_url, education, work_experience, resume_url
                    ) VALUES (
                        :job_id, :full_name, :email, :linkedin_url, :education, :work_experience, :resume_url
                    )
                """)
                conn.execute(query, {
                    "job_id": job_id,
                    "full_name": data['full_name'],
                    "email": data['email'],
                    "linkedin_url": data['linkedin_url'],
                    "education": data['education'],
                    "work_experience": data['work_experience'],
                    "resume_url": data['resume_url']
                })


def get_applicants(page=1, per_page=10, sort='newest', job_id=None, education=None, keyword=None):
    offset = (page - 1) * per_page
    filters = []
    params = {}

    base_query = """
    SELECT a.*, j.title AS job_title 
    FROM applications a
    LEFT JOIN jobs j ON a.job_id = j.id
    """

    # Filters
    if job_id:
        filters.append("a.job_id = :job_id")
        params["job_id"] = job_id
    if education:
        filters.append("LOWER(a.education) LIKE :education")
        params["education"] = f"%{education.lower()}%"
    if keyword:
        filters.append("(LOWER(a.education) LIKE :keyword OR LOWER(a.work_experience) LIKE :keyword)")
        params["keyword"] = f"%{keyword.lower()}%"

    if filters:
        base_query += " WHERE " + " AND ".join(filters)

    # Sorting
    if sort == 'oldest':
        base_query += " ORDER BY a.created_at ASC"
    else:
        base_query += " ORDER BY a.created_at DESC"

    base_query += " LIMIT :limit OFFSET :offset"
    params["limit"] = per_page
    params["offset"] = offset

    with engine.connect() as conn:
        result = conn.execute(text(base_query), params)
        applicants = [dict(row._mapping) for row in result]

    return applicants

def count_applicants(job_id=None, education=None, keyword=None):
    filters = []
    params = {}
    query = "SELECT COUNT(*) FROM applications a"

    if job_id:
        filters.append("a.job_id = :job_id")
        params["job_id"] = job_id
    if education:
        filters.append("LOWER(a.education) LIKE :education")
        params["education"] = f"%{education.lower()}%"
    if keyword:
        filters.append("(LOWER(a.education) LIKE :keyword OR LOWER(a.work_experience) LIKE :keyword)")
        params["keyword"] = f"%{keyword.lower()}%"

    if filters:
        query += " WHERE " + " AND ".join(filters)

    with engine.connect() as conn:
        result = conn.execute(text(query), params)
        return result.scalar()


def get_unique_education_levels():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT DISTINCT education FROM applications WHERE education IS NOT NULL AND education != ''"))
        return [row[0] for row in result]

def add_user(username, email, password, role="student"):
    hashed_password = generate_password_hash(password)

    try:
        with engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO users (username, email, password, role)
                    VALUES (:username, :email, :password, :role)
                """),
                {
                    "username": username,
                    "email": email,
                    "password": hashed_password,
                    "role": role
                }
            )
        return True
    except Exception as e:
        print("User creation error:", e)
        return False

def get_user_by_email(email):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM users WHERE email = :email"),
            {"email": email}
        )
        row = result.first()
        return dict(row._mapping) if row else None

def get_user_by_username(username):
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT id FROM users WHERE username = :username"),
            {"username": username}
        )
        return result.first() is not None

def enroll_student(course_id: int, user_id: int) -> bool:
    """
    Enroll a student into a course.
    Returns True if successful, False if the student is already enrolled.
    """
    with engine.connect() as conn:
        # Check if already enrolled
        existing = conn.execute(
            text("SELECT * FROM enrollments WHERE course_id = :course_id AND user_id = :user_id"),
            {"course_id": course_id, "user_id": user_id}
        ).first()

        if existing:
            return False  # Already enrolled

        # Insert enrollment
        conn.execute(
            text("""
                INSERT INTO enrollments (course_id, user_id)
                VALUES (:course_id, :user_id)
            """),
            {"course_id": course_id, "user_id": user_id}
        )
        conn.commit()
        return True

def is_user_enrolled(user_id, course_id):
    """
    Returns True if the user is already enrolled in the course.
    """
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM enrollments WHERE user_id = :user_id AND course_id = :course_id"),
            {"user_id": user_id, "course_id": course_id}
        ).first()
        return result is not None

def get_enrolled_courses(user_id):
    query = text("""
        SELECT 
            c.id,
            c.title,
            c.slug,
            c.subject,
            c.level,
            c.duration,
            c.thumbnail
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        WHERE e.user_id = :user_id
        ORDER BY e.created_at DESC
    """)

    with engine.connect() as conn:
        result = conn.execute(query, {"user_id": user_id})
        courses = [dict(row._mapping) for row in result]

    return courses

def get_quiz_courses(user_id):
    with engine.connect() as conn:

        # 1️⃣ First, calculate lesson progress per course separately
        result = conn.execute(text("""
            SELECT
                c.id,
                c.title,
                c.slug,
                q.id AS quiz_id,
                q.title AS quiz_title,
                MAX(qa.percentage) AS best_percentage,

                -- calculate progress safely
                IFNULL(
                    ROUND(
                        (
                            SELECT COUNT(*)
                            FROM lesson_progress lp
                            WHERE lp.user_id = e.user_id
                              AND lp.course_id = c.id
                              AND lp.completed = 1
                        ) /
                        NULLIF(
                            (SELECT COUNT(*) FROM course_lessons WHERE course_id = c.id),
                            0
                        ) * 100
                    ),
                    0
                ) AS progress

            FROM enrollments e
            JOIN courses c ON e.course_id = c.id

            LEFT JOIN quizzes q ON q.course_id = c.id

            LEFT JOIN quiz_attempts qa
                ON qa.quiz_id = q.id
               AND qa.user_id = e.user_id
               AND qa.completed = 1

            WHERE e.user_id = :user_id
            GROUP BY c.id, q.id
        """), {"user_id": user_id})

        return result.mappings().all()


def get_user_progress(user_id):
    """
    Returns a list of courses with total lessons and completed lessons per course.
    """
    with engine.connect() as conn:
        query = text("""
            SELECT 
                c.id AS course_id,
                c.title AS course_title,
                COUNT(cl.id) AS total_lessons,
                COUNT(lp.lesson_id) AS completed_lessons
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN course_lessons cl ON cl.course_id = c.id
            LEFT JOIN lesson_progress lp 
                ON lp.lesson_id = cl.id AND lp.user_id = e.user_id AND lp.completed = 1
            WHERE e.user_id = :user_id
            GROUP BY c.id
        """)
        result = conn.execute(query, {"user_id": user_id})
        return result.mappings().all()

def get_or_create_attempt(user_id, quiz_id):
    with engine.connect() as conn:

        attempt = conn.execute(text("""
            SELECT * FROM quiz_attempts
            WHERE user_id=:uid AND quiz_id=:qid AND completed=0
        """), {
            "uid": user_id,
            "qid": quiz_id
        }).first()

        if attempt:
            return attempt.id

        result = conn.execute(text("""
            INSERT INTO quiz_attempts (user_id, quiz_id, completed)
            VALUES (:uid, :qid, 0)
        """), {
            "uid": user_id,
            "qid": quiz_id
        })

        conn.commit()
        return result.lastrowid


def get_next_questions(quiz_id, user_id, limit=3):
    with engine.connect() as conn:
        return conn.execute(text("""
            SELECT q.*
            FROM quiz_questions q
            WHERE q.quiz_id = :qid
            AND q.id NOT IN (
                SELECT question_id
                FROM quiz_answers a
                JOIN quiz_attempts t ON a.attempt_id = t.id
                WHERE t.user_id = :uid AND t.quiz_id = :qid
            )
            ORDER BY q.id
            LIMIT :lim
        """), {
            "qid": quiz_id,
            "uid": user_id,
            "lim": limit
        }).fetchall()

def save_answers(form, user_id, quiz_id):
    with engine.connect() as conn:

        attempt = conn.execute(text("""
            SELECT * FROM quiz_attempts
            WHERE user_id = :uid
            AND quiz_id = :qid
            AND completed = 0
        """), {
            "uid": user_id,
            "qid": quiz_id
        }).first()

        if not attempt:
            return  # safety guard

        for key, value in form.items():
            if not key.startswith("q"):
                continue

            qid = int(key.replace("q", ""))

            correct = conn.execute(
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
                "ok": value == correct
            })

        conn.commit()

def require_enrollment(user_id, course_id, conn) -> bool:
    result = conn.execute(
        text("""
            SELECT 1 FROM enrollments
            WHERE user_id=:uid AND course_id=:cid
        """),
        {"uid": user_id, "cid": course_id}
    ).first()

    return result is not None


def get_user_exams(user_id):
    """Get exams available for a user - only for enrolled courses"""
    with engine.connect() as conn:
        exams = conn.execute(text("""
            SELECT 
                e.id,
                e.title,
                e.slug,
                e.description,
                e.duration_minutes,
                e.total_marks,
                c.title as course_title,
                -- Check if user has completed all lessons AND is enrolled in course
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM course_lessons cl
                        WHERE cl.course_id = e.course_id
                    ) AND (
                        SELECT COUNT(*) FROM lesson_progress lp
                        WHERE lp.user_id = :user_id 
                        AND lp.course_id = e.course_id 
                        AND lp.completed = 1
                    ) = (
                        SELECT COUNT(*) FROM course_lessons cl
                        WHERE cl.course_id = e.course_id
                    ) AND EXISTS (
                        SELECT 1 FROM enrollments en
                        WHERE en.user_id = :user_id 
                        AND en.course_id = e.course_id
                    ) THEN 1
                    ELSE 0
                END as unlocked,
                -- Get latest attempt status (excluding disqualified)
                (SELECT ea.status 
                 FROM exam_attempts ea 
                 WHERE ea.exam_id = e.id 
                 AND ea.user_id = :user_id
                 AND ea.status != 'disqualified'
                 ORDER BY ea.started_at DESC 
                 LIMIT 1) as attempt_status,
                -- Get final score from latest non-disqualified attempt
                (SELECT ea.final_score 
                 FROM exam_attempts ea 
                 WHERE ea.exam_id = e.id 
                 AND ea.user_id = :user_id
                 AND ea.status != 'disqualified'
                 ORDER BY ea.started_at DESC 
                 LIMIT 1) as final_score,
                -- Check if user has ANY disqualified attempt for this exam
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM exam_attempts ea2
                        WHERE ea2.exam_id = e.id
                        AND ea2.user_id = :user_id
                        AND ea2.status = 'disqualified'
                    ) THEN 1
                    ELSE 0
                END as is_disqualified
            FROM exams e
            JOIN courses c ON e.course_id = c.id
            WHERE e.is_published = 1
            -- Only show exams for courses user is enrolled in
            AND EXISTS (
                SELECT 1 FROM enrollments en
                WHERE en.user_id = :user_id
                AND en.course_id = e.course_id
            )
            ORDER BY e.created_at DESC
        """), {"user_id": user_id}).mappings().all()

    return [dict(exam) for exam in exams]


def get_exam_by_slug(slug):
    """Get exam by slug"""
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT *
            FROM exams
            WHERE slug = :slug AND is_published = 1
        """), {"slug": slug}).mappings().first()
    return dict(row) if row else None

def get_active_exam_attempt(user_id, exam_slug):
    """Get active exam attempt for user"""
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT ea.*
            FROM exam_attempts ea
            JOIN exams e ON ea.exam_id = e.id
            WHERE ea.user_id = :uid
              AND e.slug = :slug
              AND ea.status = 'in_progress'
            ORDER BY ea.started_at DESC
            LIMIT 1
        """), {"uid": user_id, "slug": exam_slug}).mappings().first()
    return dict(row) if row else None

def get_exam_questions(exam_id):
    """Get all questions for an exam"""
    with engine.connect() as conn:
        questions = conn.execute(text("""
            SELECT
                id,
                question_text,
                question_type,
                marks,
                time_limit_seconds,
                position
            FROM exam_questions
            WHERE exam_id = :exam_id
            ORDER BY position ASC
        """), {"exam_id": exam_id}).mappings().all()

    return [dict(q) for q in questions]

def get_question_options(question_id):
    """Get options for a specific question"""
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT
                id AS option_id,
                option_text
            FROM exam_options
            WHERE question_id = :qid
            ORDER BY id
        """), {"qid": question_id}).mappings().all()

    return [dict(row) for row in rows]

def get_question_by_id(question_id):
    """Get question by ID"""
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT *
            FROM exam_questions
            WHERE id = :id
        """), {"id": question_id}).mappings().first()
    return dict(row) if row else None

def save_exam_answer(attempt_id, question_id, answer_text=None, selected_option_id=None):
    """Save or update exam answer"""
    with engine.connect() as conn:
        # Check if answer exists
        existing = conn.execute(text("""
            SELECT id FROM exam_answers
            WHERE attempt_id = :attempt_id
            AND question_id = :question_id
        """), {
            "attempt_id": attempt_id,
            "question_id": question_id
        }).fetchone()

        if existing:
            # Update
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
                "text": answer_text,
                "option": selected_option_id
            })
        else:
            # Insert
            conn.execute(text("""
                INSERT INTO exam_answers 
                (attempt_id, question_id, answer_text, selected_option_id)
                VALUES (:attempt_id, :question_id, :text, :option)
            """), {
                "attempt_id": attempt_id,
                "question_id": question_id,
                "text": answer_text,
                "option": selected_option_id
            })
        conn.commit()

def get_exam_attempt_by_id(attempt_id):
    """Get exam attempt by ID"""
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT * FROM exam_attempts
            WHERE id = :id
        """), {"id": attempt_id}).mappings().first()
    return dict(row) if row else None

def get_user_exam_attempts(user_id, exam_id):
    """Get all attempts for user on an exam"""
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT * FROM exam_attempts
            WHERE user_id = :user_id
            AND exam_id = :exam_id
            ORDER BY started_at DESC
        """), {
            "user_id": user_id,
            "exam_id": exam_id
        }).mappings().all()
    return [dict(row) for row in rows]