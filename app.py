# pyright: reportMissingModuleSource=false
# pyright: reportMissingImports=false
# set up database connection
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import psycopg2
from collections import defaultdict
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'mydevelopmentsecret123'  # Required for flashing messages and session

bcrypt = Bcrypt(app)

# Database connection function
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT", 5432)
    )
    return conn


@app.after_request
def add_header(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    return response

#Home page (Login page)
@app.route('/')
def home():
    print("Rendering login.html")
    return render_template('login.html')

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        identifier = request.form['identifier']  # roll_number or faculty_code
        course = request.form['course']
        role = request.form['role']  # 'student' or 'faculty'
        current_semester = request.form['semester'] if role == 'student' else None
        password = request.form['password']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            if role == 'student':
                cursor.execute(
                    'INSERT INTO students (name, roll_number, course, current_semester, password) VALUES (%s, %s, %s, %s, %s)',
                    (name, identifier, course, current_semester, hashed_password)
                )
            elif role == 'faculty':
                cursor.execute(
                    'INSERT INTO faculty (name, faculty_code, course, password) VALUES (%s, %s, %s, %s)',
                    (name, identifier, course, hashed_password)
                )
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('home'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash('Identifier already exists. Please use a unique one.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

# Login handling
@app.route('/login', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == 'POST':
        identifier = request.form['identifier']  # roll_number or faculty_code
        password = request.form['password']
        role = request.form['role']  # 'student' or 'faculty'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if role == 'student':
            cursor.execute('SELECT * FROM students WHERE roll_number = %s', (identifier,))
            user = cursor.fetchone()
        elif role == 'faculty':
            cursor.execute('SELECT * FROM faculty WHERE faculty_code = %s', (identifier,))
            user = cursor.fetchone()
            
        cursor.close()
        conn.close()
            
        if user:
            if role == 'student':
                db_password = user[4]  # hashed password (in Students table)
                user_name = user[1]  # student name
                user_course = user[3]  # student course
                user_roll_number = user[2]
                user_semester = user[5]
            elif role == 'faculty':
                db_password = user[4]  # hashed password (in Faculty table)
                user_name = user[1]  # faculty name
                user_course = user[3]  # faculty course
                
            if bcrypt.check_password_hash(db_password, password):
                session['user_id'] = user[0]  # user_id
                session['name'] = user_name  # name
                session['course'] = user_course  # course
                session['role'] = role  # role (student/faculty)
                if role == 'student':
                    session['student_id'] = user[0]
                    session['roll_number'] = user_roll_number  # ✅ Important for student dashboard
                    session['current_semester'] = user_semester
                    flash('Login successful!', 'success')
                    return redirect(url_for('student_dashboard'))
                
                elif role == 'faculty':
                    session['faculty_id'] = user[0]
                    flash('Login successful!', 'success')
                    return redirect(url_for('faculty_dashboard'))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('User not found. Please register first.', 'danger')
            
        return redirect(url_for('login'))
    
    return render_template('login.html')


# Forgot Password Handling
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        roll_number = request.form['roll_no']
        course = request.form['course']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if the passwords match
        if new_password != confirm_password:
            flash("Passwords do not match!", 'error')
            return redirect(url_for('forgot_password'))

        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Database connection inside the route
        conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
        cursor = conn.cursor()

        # Check for student
        cursor.execute("SELECT * FROM students WHERE name = %s AND roll_number = %s AND course = %s", 
                       (username, roll_number, course))
        student = cursor.fetchone()

        # Check for faculty
        cursor.execute("SELECT * FROM faculty WHERE name = %s AND faculty_code = %s AND course = %s", 
                       (username, roll_number, course))
        faculty = cursor.fetchone()

        if student:
            # Update student password
            cursor.execute("UPDATE students SET password = %s WHERE name = %s AND roll_number = %s", 
                           (hashed_password, username, roll_number))
            conn.commit()
            flash("Password updated successfully for student!", 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        elif faculty:
            # Update faculty password
            cursor.execute("UPDATE faculty SET password = %s WHERE name = %s AND faculty_code = %s", 
                           (hashed_password, username, roll_number))
            conn.commit()
            flash("Password updated successfully for faculty!", 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        else:
            flash("No account found with the provided details!", 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


# Student dashboard
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))
    name = session.get('name')
    course = session.get('course')
    roll_number = session.get('roll_number')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the latest semester (current_semester) from the database
    cursor.execute("""
        SELECT current_semester FROM Students WHERE roll_number = %s
    """, (roll_number,))
    semester_row = cursor.fetchone()
    if semester_row:
        current_semester = semester_row[0]
    else:
        flash("Semester info not found.", "danger")
        return redirect(url_for('logout'))

    # Save current semester to session
    session['semester'] = current_semester
    
    # Get today's date and day
    today_date = datetime.now().strftime("%d %B %Y")
    today_day = datetime.now().strftime("%A")
    today = f"{today_day}, {today_date}"

    cursor.close()
    conn.close()

    # Create a simple profile avatar as the first letter of the student's name.
    profile_avatar = name[0].upper()

    semesters = list(range(1, 7)) 

    return render_template(
        'student_dashboard.html',
        name=name,
        profile_avatar=profile_avatar,
        course=course,
        today_date=today_date,
        today_day=today_day,
        selected_semester=current_semester,
        current_semester=current_semester,
        semesters=semesters
    )

# Faculty dashboard
@app.route('/faculty/dashboard')
def faculty_dashboard():
    if 'user_id' not in session or session.get('role') != 'faculty':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))
    
    name = session.get('name')
    faculty_id = session.get('faculty_id')
    course = session.get('course')

    # Create a simple profile avatar using the first letter of the faculty's name
    profile_avatar = name[0].upper() if name else "?"

    # Get selected semester from query string; default to 1
    selected_semester = request.args.get('semester', default=1, type=int)

    # Date and Day
    today_date = datetime.now().strftime("%d %B %Y")
    today_day = datetime.now().strftime("%A")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Debugging: Check the selected semester and faculty ID
    print(f"Selected Semester: {selected_semester}, Faculty ID: {faculty_id}, Course: {course}")
    
    cursor.close()
    conn.close()

    semesters = list(range(1, 7)) 

    return render_template(
        'faculty_dashboard.html',
        name=name,
        profile_avatar=profile_avatar,
        course=course,
        today_date=today_date,
        today_day=today_day,
        selected_semester=selected_semester,
        semesters=semesters
    )

# Choose Subjects
@app.route('/choose_subjects/<int:semester>', methods=['GET', 'POST'])
def choose_subjects(semester):
    if 'faculty_id' not in session:
        return redirect(url_for('login'))

    faculty_id = session['faculty_id']
    course = session.get('course') 
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch unassigned subjects for that semester and course (faculty_id is NULL)
    cursor.execute("""
        SELECT * FROM subjects WHERE semester = %s AND course = %s AND faculty_id IS NULL
    """, (semester, course))
    subjects = []
    for row in cursor.fetchall():
        subject = {
            "subject_id": row[0],  # Assuming subject_id is the first column
            "subject_name": row[3],  # Assuming subject_name is the second column
        }
        subjects.append(subject)

    # Fetch subjects already assigned to the faculty
    cursor.execute("""
                   SELECT * FROM subjects
                   WHERE semester = %s AND course = %s
    """, (semester, course))

    assigned_subjects = []
    for row in cursor.fetchall():
        if row[4] == faculty_id:  # index 4 is faculty_id
            assigned_subjects.append({
                "subject_id": row[0],
                "subject_name": row[3],
            })


    if request.method == 'POST':
        selected_subjects = request.form.getlist('subjects')  # Selected subjects to assign
        unassign_subjects = request.form.getlist('unassign_subjects')  # Selected subjects to unassign

        # Assign the faculty_id to the selected subjects
        for subject_id in selected_subjects:
            cursor.execute("""
                UPDATE subjects SET faculty_id = %s WHERE subject_id = %s
            """, (faculty_id, subject_id))

        # Unassign the faculty_id from selected subjects
        for subject_id in unassign_subjects:
            cursor.execute("""
                UPDATE subjects SET faculty_id = NULL WHERE subject_id = %s
            """, (subject_id,))

        # Commit the changes to the database
        conn.commit()
        flash("Changes saved successfully!", "success")
        return redirect(url_for('faculty_dashboard', semester=semester))

    cursor.close()
    conn.close()

    return render_template('choose_subjects.html', semester=semester, subjects=subjects, assigned_subjects=assigned_subjects)

# Student & Subject Handling
@app.route('/student/semester/<int:semester>/subjects', methods=['GET', 'POST'])
def student_subjects(semester):
    if 'student_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    course = session.get('course')  # Get the course from the session
    student_id = session.get('student_id')

    if not course:
        return "Error: Course not found for the logged-in student."

    # Database connection
    conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
    cursor = conn.cursor()

    # Always fetch the latest current_semester for student
    cursor.execute("SELECT current_semester FROM Students WHERE student_id = %s", (student_id,))
    semester_row = cursor.fetchone()
    if semester_row:
        current_semester = semester_row[0]
    else:
        flash("Semester info not found.", "danger")
        return redirect(url_for('logout'))

    # SQL query to get subjects and their faculty members
    cursor.execute("""
        SELECT s.subject_name, f.name AS faculty_name
        FROM subjects s
        JOIN faculty f ON s.faculty_id = f.faculty_id
        WHERE s.course = %s AND s.semester = %s
    """, (course, semester))

    # Fetching results
    subjects_and_faculties = cursor.fetchall()

    print(subjects_and_faculties)  # Debugging output, ensure data is coming through

    # Closing the connection
    cursor.close()
    conn.close()

    # Pass the fetched subjects data to the template
    return render_template('student_subjects.html', semester=semester, subjects=subjects_and_faculties)

# Student Feedback Handling
@app.route('/student/semester/<semester>/feedback', methods=['GET', 'POST'])
def feedback_form(semester):
    if 'student_id' not in session:  # Ensure the student is logged in
        return redirect(url_for('login'))

    student_id = session['student_id']

    # Fetch the logged-in student's course from the database
    conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
    cursor = conn.cursor()

    cursor.execute("SELECT course, current_semester FROM Students WHERE student_id = %s", (student_id,))
    student_row = cursor.fetchone()
    if student_row:
        student_course = student_row[0]
        current_semester = student_row[1]
    else:
        return redirect(url_for('logout'))

    if request.method == 'POST':
        feedback_text = request.form.get('feedback')

        if feedback_text:
            cursor.execute(
                "INSERT INTO feedbacks (semester, feedback_text, submitted_at, course, student_id) VALUES (%s, %s, %s, %s, %s)",
                (semester, feedback_text, datetime.now(), student_course, student_id)
            )
            conn.commit()
            return redirect(url_for('feedback_submitted'))
        else:
            flash('Please write something before submitting.', 'error')
            return redirect(url_for('feedback_form', semester=current_semester))

    return render_template('student_feedback.html', semester=current_semester)


@app.route('/feedback_submitted')
def feedback_submitted():
    semesters = request.args.get('semester') 
    return render_template('feedback_submitted.html')

#View Feedbacks Handling
@app.route('/view-feedbacks/<semester>', methods=['GET'])
def view_feedbacks(semester):
    if 'faculty_id' not in session:  # Ensure the faculty is logged in
        return redirect(url_for('faculty_login'))

    faculty_id = session['faculty_id']
    
    # Database connection
    try:
        # Establish connection
        conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
        cursor = conn.cursor()

        # Fetch the logged-in faculty's course
        cursor.execute("SELECT course FROM faculty WHERE faculty_id = %s", (faculty_id,))
        faculty_course = cursor.fetchone()[0]

        # SQL query to get feedbacks for the selected semester and faculty's course
        cursor.execute("""
            SELECT feedback_text, submitted_at
            FROM feedbacks
            WHERE semester = %s AND course = %s
        """, (semester, faculty_course))

        # Fetching results
        feedbacks = cursor.fetchall()

        # Debugging output
        print(feedbacks)

    except Exception as e:
        print(f"Error occurred: {e}")
        return "Error: Unable to fetch feedbacks."

    finally:
        # Ensure connection is closed even if an error occurs
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Pass the fetched feedback data to the template
    return render_template('view_feedbacks.html', semester=semester, feedbacks=feedbacks)

#Post Announcement Handling
@app.route('/post-announcements/<semester>', methods=['GET', 'POST'])
def post_announcements(semester):
    if 'faculty_id' not in session:
        return redirect(url_for('faculty_login'))  # Redirect to login if faculty is not logged in

    faculty_id = session['faculty_id']

    try:
        # Connect to the database and fetch the faculty's course
        conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
        cursor = conn.cursor()
        cursor.execute("SELECT course FROM faculty WHERE faculty_id = %s", (faculty_id,))
        faculty_course = cursor.fetchone()

        if not faculty_course:
            return redirect(url_for('faculty_dashboard'))

        faculty_course = faculty_course[0]  # Extracting course name

    except Exception as e:
        print(f"Error: {e}")
        flash('Error fetching faculty course data.', 'error')
        return redirect(url_for('faculty_dashboard'))

    finally:
        cursor.close()
        conn.close()

    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')

        if title and message:
            try:
                # Insert announcement into the database
                conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO announcements (faculty_id, course, semester, title, message, posted_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (faculty_id, faculty_course, semester, title, message, datetime.now()))

                conn.commit()

                return redirect(url_for('announcement_submitted'))  # Redirect to confirmation page

            except Exception as e:
                print(f"Error: {e}")
                flash('Error posting announcement. Please try again.', 'error')

        else:
            flash('Please fill in all fields.', 'error')

    return render_template('post_announcements.html', semester=semester, course=faculty_course)

@app.route('/announcement-submitted', methods=['GET'])
def announcement_submitted():
    return render_template('announcement_submitted.html')

# View Announcements Handling
@app.route('/student/semester/<semester>/announcements', methods=['GET'])
def view_announcements(semester):
    # Check if student is logged in
    if 'student_id' not in session:
        return redirect(url_for('student_login'))

    student_id = session['student_id']
    
    try:
        # Fetch student course
        conn = psycopg2.connect(dbname="student_management", user="postgres", password="harshita@05", host="localhost")
        cursor = conn.cursor()
        cursor.execute("SELECT course FROM students WHERE student_id = %s", (student_id,))
        student_course = cursor.fetchone()

        if not student_course:
            flash('Course not found.', 'error')
            return redirect(url_for('student_dashboard'))
        
        # Always fetch the current semester
        cursor.execute("SELECT current_semester FROM Students WHERE student_id = %s", (student_id,))
        semester_row = cursor.fetchone()
        if semester_row:
            current_semester = semester_row[0]
        else:
            flash("Semester info not found.", "error")
            return redirect(url_for('student_dashboard'))

        # Fetch announcements based on course and semester
        cursor.execute("""
            SELECT title, message, posted_at FROM announcements
            WHERE course = %s AND semester = %s
            ORDER BY posted_at DESC
        """, (student_course[0], semester))

        announcements = cursor.fetchall()

    except Exception as e:
        flash('Error fetching announcements.', 'error')
        return redirect(url_for('student_dashboard'))

    finally:
        cursor.close()
        conn.close()

    return render_template('view_announcements.html', announcements=announcements, semester=semester)

# mark Attendance Handling
@app.route('/mark-attendance/<semester>', methods=['GET', 'POST'])
def mark_attendance(semester):

    # Create connection inside the route
    conn = psycopg2.connect(host="localhost", database="student_management", user="postgres", password="harshita@05")
    cur = conn.cursor()

    faculty_id = session['faculty_id']
    course = session.get('course')

    if not semester or not course:
        cur.close()
        conn.close()
        return redirect('/faculty/dashboard')

    if request.method == 'POST':
        # Handling form submission
        subject_name = request.form['subject']
        date = request.form['date']

        # Fetch students to map roll numbers
        cur.execute("""
            SELECT student_id, roll_number FROM students
            WHERE current_semester = %s AND course = %s
        """, (semester, course))
        students = cur.fetchall()

        attendance_records = []
        for student_id, roll_number in students:
            attendance_status = request.form.get(f'attendance_{roll_number}')
            if attendance_status:
                attendance_records.append((
                    faculty_id, student_id, subject_name, date,
                    'Present' if attendance_status.lower() == 'present' else 'Absent',
                    semester, course
                ))

        if attendance_records:
            cur.executemany("""
                INSERT INTO attendance (faculty_id, student_id, subject_name, date, status, semester, course)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, attendance_records)
            conn.commit()

        cur.close()
        conn.close()
        return redirect('/faculty/dashboard')

    else:
        # GET: Show the form
        cur.execute("""
            SELECT subject_name FROM subjects
            WHERE faculty_id = %s AND semester = %s AND course = %s
        """, (faculty_id, semester, course))
        subjects = [row[0] for row in cur.fetchall()]

        cur.execute("""
            SELECT student_id, name, roll_number FROM students
            WHERE current_semester = %s AND course = %s
            ORDER BY roll_number ASC        
        """, (semester, course))
        students = [{'student_id': row[0], 'name': row[1], 'roll_number': row[2]} for row in cur.fetchall()]

        cur.close()
        conn.close()

        return render_template('mark_attendance.html', subjects=subjects, students=students, semester=semester)

# View Attendance Handling
@app.route('/student/semester/<semester>/attendance')
def view_attendance(semester):
    if 'student_id' not in session:
        return redirect('/student/login')

    student_id = session['student_id']
    course = session.get('course')

    # Create connection
    conn = psycopg2.connect(host="localhost", database="student_management", user="postgres", password="harshita@05")
    cur = conn.cursor()

    # Fetch subjects for the student's course and semester
    cur.execute("""
        SELECT subject_name FROM subjects
        WHERE semester = %s AND course = %s
    """, (semester, course))
    subjects = [{'subject_name': row[0]} for row in cur.fetchall()]

    # Fetch all attendance records for this student
    cur.execute("""
        SELECT date, subject_name, status FROM attendance
        WHERE student_id = %s AND semester = %s AND course = %s
        ORDER BY date ASC
    """, (student_id, semester, course))
    records = cur.fetchall()

    attendance_data = {}
    for date, subject_name, status in records:
        if date not in attendance_data:
            attendance_data[date] = {}
        attendance_data[date][subject_name] = status

    # Calculate attendance percentage per subject
    subject_attendance = {}
    for subject in subjects:
        subject_name = subject['subject_name']
        total_classes = sum(1 for date_attendance in attendance_data.values() if subject_name in date_attendance)
        present_classes = sum(1 for date_attendance in attendance_data.values() if date_attendance.get(subject_name) == 'Present')

        if total_classes > 0:
            percentage = round((present_classes / total_classes) * 100, 2)
        else:
            percentage = 0.0

        subject_attendance[subject_name] = {
            'total': total_classes,
            'present': present_classes,
            'percentage': percentage
        }

    cur.close()
    conn.close()

    return render_template('view_attendance.html', subjects=subjects, attendance_data=attendance_data, subject_attendance=subject_attendance, semester=semester)

# Student Timetable Handling
@app.route('/student/semester/<semester>/timetable')
def view_timetable(semester):
    if 'student_id' not in session:
        return redirect('/student/login')

    course = session.get('course')
    if not course:
        return redirect('/student/dashboard')  # fallback safety

    # Define the format_subject filter inside the route
    def format_subject_name(subject):
        if subject and len(subject) > 18 and ' ' in subject:
            words = subject.split()
            half = len(words) // 2
            return ' '.join(words[:half]) + '<br>' + ' '.join(words[half:])
        return subject

    # Register the filter with Jinja
    app.jinja_env.filters['format_subject'] = format_subject_name

    # Connect to the PostgreSQL database
    conn = psycopg2.connect(host="localhost", database="student_management", user="postgres", password="harshita@05")
    cur = conn.cursor()

    # Fetch timetable data with subject and faculty info
    cur.execute("""
        SELECT 
            tt.day, 
            tt.slot, 
            s.subject_name, 
            f.name AS faculty_name
        FROM timetable tt
        JOIN subjects s ON tt.subject_id = s.subject_id
        LEFT JOIN faculty f ON s.faculty_id = f.faculty_id
        WHERE tt.semester = %s AND tt.course = %s
        ORDER BY tt.day, tt.slot;
    """, (semester, course))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Prepare a dictionary for timetable display
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
    timetable = {day: [None]*7 for day in days}

    for day, slot, subject, faculty in rows:
        if slot == 4:  # Skip break
            continue
        timetable[day][slot] = {
            'subject': subject,
            'faculty': faculty if faculty else "NA"
        }

    # Fill empty slots with default
    for day in days:
        for i in range(7):
            if timetable[day][i] is None:
                timetable[day][i] = {'subject': None, 'faculty': None}

    return render_template('student_timetable.html', semester=semester, course=course, timetable=timetable)

# Faculty TimeTable Handling
@app.route('/faculty-timetable/<semester>')
def faculty_timetable(semester):
    if 'faculty_id' not in session or 'course' not in session:
        return redirect(url_for('login'))

    faculty_id = session['faculty_id']
    course = session['course']

    # Connect to PostgreSQL
    conn = psycopg2.connect(
        host="localhost",
        database="student_management",
        user="postgres",
        password="harshita@05"
    )
    cur = conn.cursor()

    # Step 1: Get subject_ids assigned to this faculty for selected semester & course
    cur.execute("""
        SELECT subject_id, subject_name
        FROM subjects
        WHERE faculty_id = %s AND semester = %s AND course = %s
    """, (faculty_id, semester, course))

    subject_map = {row[0]: row[1] for row in cur.fetchall()}
    if not subject_map:
        cur.close()
        conn.close()
        return render_template('faculty_timetable.html', timetable=None)

    subject_ids = tuple(subject_map.keys())

    # Step 2: Get timetable entries for these subject_ids
    cur.execute(f"""
        SELECT day, slot, subject_id
        FROM timetable
        WHERE semester = %s AND course = %s AND subject_id IN %s
    """, (semester, course, subject_ids))

    # Step 3: Structure data into a timetable[day][slot] = subject_name
    timetable = defaultdict(lambda: defaultdict(str))
    for day, slot, subject_id in cur.fetchall():
        timetable[day][slot] = subject_map.get(subject_id, "Unknown Subject")

    cur.close()
    conn.close()

    return render_template('faculty_timetable.html', timetable=timetable)
# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
 app.run(debug=True)

