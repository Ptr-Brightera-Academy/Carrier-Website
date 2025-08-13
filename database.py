import os
from sqlalchemy import create_engine, text


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
        result = conn.execute(text("SELECT * FROM courses"))
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
