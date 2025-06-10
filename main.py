from flask import Flask, render_template, request, jsonify, url_for, redirect
import google.generativeai as genai
import os
import PyPDF2
import logging
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message
import pytz
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'  # Add this line for session support
CORS(app)  # Enable CORS if frontend is separate

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load Google API key and configure model
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    raise RuntimeError("GOOGLE_API_KEY is not set in environment variables")

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration (demo values, replace with real credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'donaldmini10@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'oeuv osur uwzf smnh'     # Replace with your app password
app.config['MAIL_DEFAULT_SENDER'] = 'donaldmini10@gmail.com'

mail = Mail(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Add this line for migrations

# Define models for persistence

class SimulationResult(db.Model):
    __tablename__ = 'simulation_results'

    id = db.Column(db.Integer, primary_key=True)
    sim_type = db.Column(db.String(100), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)  # 'success' or 'failure'
    action = db.Column(db.String(20), nullable=False)   # 'reported' or 'fell_for_it'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        IST = pytz.timezone('Asia/Kolkata')
        ist_timestamp = self.timestamp.replace(tzinfo=pytz.utc).astimezone(IST)
        return {
            'type': self.sim_type,
            'outcome': self.outcome,
            'action': self.action,
            'timestamp': ist_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

class ScheduledSimulation(db.Model):
    __tablename__ = 'scheduled_simulations'

    id = db.Column(db.Integer, primary_key=True)
    sim_type = db.Column(db.String(100), nullable=False)
    target_group = db.Column(db.String(200), nullable=False)
    launch_date = db.Column(db.Date, nullable=False)
    completion_date = db.Column(db.Date, nullable=False)
    scheduled_at = db.Column(db.DateTime, default=datetime.utcnow)
    triggered = db.Column(db.Boolean, default=False)
    triggered_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        IST = pytz.timezone('Asia/Kolkata')
        ist_launch_date = self.launch_date
        ist_completion_date = self.completion_date
        ist_scheduled_at = self.scheduled_at.replace(tzinfo=pytz.utc).astimezone(IST)
        ist_triggered_at = self.triggered_at.replace(tzinfo=pytz.utc).astimezone(IST) if self.triggered_at else None
        return {
            'type': self.sim_type,
            'target_group': self.target_group,
            'launch_date': ist_launch_date.strftime("%Y-%m-%d"),
            'completion_date': ist_completion_date.strftime("%Y-%m-%d"),
            'scheduled_at': ist_scheduled_at.strftime("%Y-%m-%d %H:%M:%S"),
            'triggered': self.triggered,
            'triggered_at': ist_triggered_at.strftime("%Y-%m-%d %H:%M:%S") if ist_triggered_at else None
        }

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Helper functions for prediction

def predict_fake_or_real_email_content(text):
    try:
        prompt = f"""
You are an expert in identifying scam messages. Analyze the text and classify it as:
- Real/Legitimate
- Scam/Fake

Text: {text}

Return only the classification message.
"""
        response = model.generate_content(prompt)
        # Defensive check for response and .text
        return response.text.strip() if response and hasattr(response, "text") else "Classification failed."
    except Exception as e:
        logging.error(f"Error predicting fake or real email content: {e}")
        return "Error predicting fake or real email content."

def url_detection(url):
    try:
        prompt = f"""
Analyze this URL and classify it as:
1. benign
2. phishing
3. malware
4. defacement

URL: {url}

Return only the classification.
"""
        response = model.generate_content(prompt)
        return response.text.strip().lower() if response and hasattr(response, "text") else "unknown"
    except Exception as e:
        logging.error(f"Error detecting URL: {e}")
        return "Error detecting URL."

# Routes

@app.route('/')
def home():
    print('User authenticated:', current_user.is_authenticated)
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template("landing.html")

@app.route('/learnmore')
@login_required
def learnmore():
    return render_template("learnmore.html")

@app.route('/detection')
@login_required
def detection_page():
    return render_template("detection.html")

@app.route('/awareness')
@login_required
def awareness():
    return render_template("awareness.html")

@app.route('/quiz')
@login_required
def quiz_page():
    return render_template("quiz.html")

@app.route('/simulation')
@login_required
def simulation_page():
    return render_template("simulation.html")

@app.route('/log_simulation', methods=['POST'])
def log_simulation():
    try:
        data = request.json
        print('Received log_simulation POST:', data)
        sim_result = SimulationResult(
            sim_type=data.get('type'),
            outcome=data.get('outcome'),
            action=data.get('action'),
            timestamp=datetime.utcnow()
        )
        db.session.add(sim_result)
        db.session.commit()
        print('SimulationResult committed to DB')
        return jsonify({'status': 'success'})
    except Exception as e:
        print('Error in log_simulation:', e)
        logging.error(f"Error logging simulation: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_simulation_stats', methods=['GET'])
def get_simulation_stats():
    try:
        results = SimulationResult.query.all()
        total = len(results)
        success_count = sum(1 for r in results if r.outcome == 'success')
        success_rate = round((success_count / total) * 100, 1) if total > 0 else 0
        
        # Count simulation types
        type_counts = defaultdict(int)
        for r in results:
            type_counts[r.sim_type] += 1
        common_type = max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else "N/A"

        # Most recent timestamp (convert to IST)
        most_recent_obj = SimulationResult.query.order_by(SimulationResult.timestamp.desc()).first()
        if most_recent_obj:
            IST = pytz.timezone('Asia/Kolkata')
            most_recent_ist = most_recent_obj.timestamp.replace(tzinfo=pytz.utc).astimezone(IST)
            most_recent = most_recent_ist.strftime("%Y-%m-%d %H:%M:%S")
        else:
            most_recent = "N/A"

        return jsonify({
            'total_simulations': total,
            'success_rate': success_rate,
            'most_recent': most_recent,
            'common_type': common_type
        })
    except Exception as e:
        logging.error(f"Error getting simulation stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/schedule_simulation', methods=['POST'])
def schedule_simulation():
    try:
        data = request.json
        launch_date = datetime.strptime(data.get('launch_date'), "%Y-%m-%d").date()
        completion_date = datetime.strptime(data.get('completion_date'), "%Y-%m-%d").date()

        scheduled = ScheduledSimulation(
            sim_type=data.get('simulation_type'),
            target_group=data.get('target_group'),
            launch_date=launch_date,
            completion_date=completion_date,
            scheduled_at=datetime.utcnow()
        )
        db.session.add(scheduled)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"Error scheduling simulation: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/scam/', methods=['POST'])
def detect_scam():
    try:
        if 'file' not in request.files:
            return render_template("detection.html", message="No file uploaded.")

        file = request.files['file']
        if file.filename == '':
            return render_template("detection.html", message="No file selected.")

        if not (file.filename.lower().endswith('.pdf') or file.filename.lower().endswith('.txt')):
            return render_template("detection.html", message="Invalid file type. Please upload PDF or TXT.")

        extracted_text = ""
        if file.filename.lower().endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(file)
            # Defensive extraction to handle None returns
            extracted_text = " ".join([page.extract_text() or "" for page in pdf_reader.pages])
        else:
            extracted_text = file.read().decode("utf-8")

        if not extracted_text.strip():
            return render_template("detection.html", message="File is empty or text could not be extracted.")

        message = predict_fake_or_real_email_content(extracted_text)
        return render_template("detection.html", message=message)
    except Exception as e:
        logging.error(f"Error detecting scam: {e}")
        return render_template("detection.html", message="Error detecting scam.")

@app.route('/predict', methods=['POST'])
def predict_url():
    try:
        url = request.form.get('url', '').strip()
        if not url:
            return render_template("detection.html", message="URL cannot be empty.")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        classification = url_detection(url)
        return render_template("detection.html", input_url=url, predicted_class=classification)
    except Exception as e:
        logging.error(f"Error predicting URL: {e}")
        return render_template("detection.html", message="Error predicting URL.")

@app.route('/get_scheduled_simulations', methods=['GET'])
def get_scheduled_simulations():
    try:
        scheduled = ScheduledSimulation.query.order_by(ScheduledSimulation.launch_date.asc()).all()
        return jsonify([s.to_dict() for s in scheduled])
    except Exception as e:
        logging.error(f"Error getting scheduled simulations: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def send_email_notification(sim):
    try:
        msg = Message(
            subject=f"Simulation Triggered: {sim.sim_type}",
            recipients=['donaldmini10@gmail.com'],
            body=f"""
A scheduled simulation has been triggered.

Type: {sim.sim_type}
Target Group: {sim.target_group}
Launch Date: {sim.launch_date}
Completion Date: {sim.completion_date}
Triggered At: {sim.triggered_at}
"""
        )
        mail.send(msg)
        logging.info(f"Notification email sent for simulation {sim.id}")
    except Exception as e:
        logging.error(f"Error sending notification email: {e}")

def trigger_due_simulations():
    with app.app_context():
        now = datetime.utcnow().date()
        due = ScheduledSimulation.query.filter(
            ScheduledSimulation.launch_date <= now,
            not ScheduledSimulation.triggered
        ).all()
        for sim in due:
            sim.triggered = True
            sim.triggered_at = datetime.utcnow()
            db.session.commit()
            logging.info(f"Triggered simulation: {sim.id} ({sim.sim_type}) for {sim.target_group}")
            send_email_notification(sim)

# Start the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(trigger_due_simulations, 'interval', minutes=1)
scheduler.start()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))  # Redirect to landing page
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_valid_password(password):
            return render_template('register.html', error='Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.')
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()  # Drop all tables (dev only!)
        db.create_all()  # Recreate tables
    app.run(debug=True)
