from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import csv
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)

# Admin credentials (these can be moved to environment variables for better security)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = hashlib.sha256('admin_password'.encode()).hexdigest()  # Use SHA-256 for password hashing

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    grades = db.relationship('Grade', backref='student', lazy=True)

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), db.ForeignKey('user.student_id'), nullable=False)
    quiz1 = db.Column(db.Float, nullable=True)
    parcial1 = db.Column(db.Float, nullable=True)
    quiz2 = db.Column(db.Float, nullable=True)
    parcial2 = db.Column(db.Float, nullable=True)
    quiz3 = db.Column(db.Float, nullable=True)
    parcial3 = db.Column(db.Float, nullable=True)
    quiz4 = db.Column(db.Float, nullable=True)
    parcial4 = db.Column(db.Float, nullable=True)

# Admin check decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        existing_user = User.query.filter_by(student_id=student_id).first()
        if existing_user:
            return render_template('register.html', error='Student ID already exists')

        new_user = User(student_id=student_id, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        user = User.query.filter_by(student_id=student_id).first()
        if user and user.password == hashlib.sha256(password.encode()).hexdigest():
            session['student_id'] = student_id
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'student_id' not in session:
        return redirect(url_for('login'))
    student_id = session['student_id']
    grades = Grade.query.filter_by(student_id=student_id).first()
    print(grades, "grades")
    return render_template('dashboard.html', grades=grades)

# Admin login
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('enter_grades'))
        return render_template('admin_login.html', error='Invalid admin credentials')
    return render_template('admin_login.html')

# Restrict access to this route to admin only
@app.route('/enter_grades', methods=['GET', 'POST'])
@admin_required
def enter_grades():
    if request.method == 'POST':
        student_id = request.form['student_id']
        parcial1 = request.form['parcial1']
        quiz1 = request.form['quiz2']
        parcial2 = request.form['parcial1']
        quiz2 = request.form['quiz2']
        grade = Grade.query.filter_by(student_id=student_id).first()
        if grade:
            grade.parcial1 = parcial1
            grade.quiz1 = quiz1
            grade.parcial2 = parcial2
            grade.quiz2 = quiz2
        else:
            new_grade = Grade(student_id=student_id, parcial1=parcial1, quiz1=quiz1,
                    parcial2 = parcial2, quiz2 = quiz2)
            db.session.add(new_grade)
        db.session.commit()
        return redirect(url_for('enter_grades'))
    students = User.query.all()  # Get all students to display in the form
    return render_template('enter_grades.html', students=students)

@app.route('/view_all_grades')
@admin_required
def view_all_grades():
    grades = Grade.query.all()
    return render_template('view_all_grades.html', grades=grades)


@app.route('/upload_grades', methods=['GET', 'POST'])
@admin_required
def upload_grades():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream, delimiter=';')
            next(csv_input)  # Skip the header row
            for row in csv_input:
                student_id = row[0]
                # Replace commas with periods in numeric columns and handle empty fields
                quiz1 = float(row[1].replace(',', '.') or 0)  # Defaults to 0 if empty
                parcial1 = float(row[2].replace(',', '.') or 0)
                quiz2 = float(row[3].replace(',', '.') or 0)
                parcial2 = float(row[4].replace(',', '.') or 0)
                quiz3 = float(row[5].replace(',', '.') or 0)
                parcial3 = float(row[6].replace(',', '.') or 0)
                quiz4 = float(row[7].replace(',', '.') or 0)
                parcial4 = float(row[8].replace(',', '.') or 0)

                grade = Grade.query.filter_by(student_id=student_id).first()

                if grade:
                    # Update existing grade
                    grade.quiz1 = quiz1
                    grade.parcial1 = parcial1
                    grade.quiz2 = quiz2
                    grade.parcial2 = parcial2
                    grade.quiz3 = quiz3
                    grade.parcial3 = parcial3
                    grade.quiz4 = quiz4
                    grade.parcial4 = parcial4
                else:
                    # Create new grade entry
                    new_grade = Grade(
                        student_id=student_id,
                        quiz1=quiz1,
                        parcial1=parcial1,
                        quiz2=quiz2,
                        parcial2=parcial2,
                        quiz3=quiz3,
                        parcial3=parcial3,
                        quiz4=quiz4,
                        parcial4=parcial4
                    )
                    db.session.add(new_grade)

                db.session.commit()

            return redirect(url_for('upload_grades'))
    return render_template('upload_grades.html')


@app.route('/logout')
def logout():
    session.pop('student_id', None)
    session.pop('admin', None)  # Clear admin session
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Drop existing tables
        db.create_all()  # Create new tables with updated schema
    app.run(debug=True)
