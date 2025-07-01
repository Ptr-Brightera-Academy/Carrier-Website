from flask import Flask, render_template
from database import get_jobs_from_db

app = Flask(__name__)
           
@app.route("/")
def hello_world():
    JOBS = get_jobs_from_db()
    return render_template('home.html', jobs=JOBS)

@app.route("/contact-us")
def contact_us():
    return "Contact Us"

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
