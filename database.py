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
        result = conn.execute(text("""
            SELECT
                c.id,
                c.title,
                c.slug,
                q.id AS quiz_id,
                q.title AS quiz_title,
                IFNULL(
                    ROUND(
                        (COUNT(lp.lesson_id) /
                        (SELECT COUNT(*) FROM course_lessons WHERE course_id = c.id)) * 100
                    ), 0
                ) AS progress
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN quizzes q ON q.course_id = c.id
            LEFT JOIN lesson_progress lp
                ON lp.course_id = c.id
                AND lp.user_id = e.user_id
                AND lp.completed = 1
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
