from flask import Flask, jsonify, render_template, request
from database import get_jobs_from_db, get_job_from_db, add_application_to_db

app = Flask(__name__)
           
@app.route("/")
def hello_world():
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
    print("Received data:", data)
    job = get_job_from_db(id)
    add_application_to_db(id, data)
    return render_template('application_submitted.html', application=data, job=job)
    
@app.route("/contact-us")
def contact_us():
    return "Contact Us"

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
