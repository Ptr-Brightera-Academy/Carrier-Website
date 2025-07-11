from flask import Flask, jsonify, render_template, request
from database import get_jobs_from_db, get_job_from_db, add_application_to_db

app = Flask(__name__)
           
@app.route("/")
def home_page():
    JOBS = get_jobs_from_db()
    return render_template('home.html', jobs=JOBS)
    
@app.route("/job/<id>")
def show_job(id):
    job = get_job_from_db(id)
    if not job:
        return "Not Found", 404
    return render_template('jobpage.html', job=job)
           
@app.route("/job/<id>/apply", methods=['post'])
def apply_to_job(id):
    data = request.form
    job = get_job_from_db(id)
    # add_application_to_db(id, data)
    return render_template('application_submitted.html', application=data, job=job)
    
@app.route("/contact_us")
def contact_us():
    return render_template('contact_us.html')

@app.route("/signup")
def signup():
    return render_template('signup.html')

@app.route("/about_us")
def about_us():
    return render_template('about_us.html')

@app.route("/services")
def services():
    return render_template('services.html')

@app.route("/faqs")
def FAQs():
    return render_template('faqs.html')
    
@app.route("/login")
def login():
    return render_template('login.html')
    
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
