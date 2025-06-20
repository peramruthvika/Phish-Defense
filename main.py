from flask import Flask, render_template, request, jsonify, url_for, redirect
import google.generativeai as genai
import os
import PyPDF2
import logging
from datetime import datetime, timedelta, timezone
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
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')


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
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sim_type = db.Column(db.String(100), nullable=False)
    target_group = db.Column(db.String(200), nullable=False)
    launch_date = db.Column(db.Date, nullable=False)
    completion_date = db.Column(db.Date, nullable=False)
    scheduled_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    triggered = db.Column(db.Boolean, default=False)
    triggered_at = db.Column(db.DateTime, nullable=True)
    notification_email = db.Column(db.String(120), nullable=False)  # Email to receive notification
    email_opened = db.Column(db.Boolean, default=False)  # Track if email was opened
    email_opened_at = db.Column(db.DateTime, nullable=True)  # When email was opened

    # Relationship to User
    user = db.relationship('User', backref='scheduled_simulations')

    def to_dict(self):
        IST = pytz.timezone('Asia/Kolkata')
        ist_launch_date = self.launch_date
        ist_completion_date = self.completion_date
        ist_scheduled_at = self.scheduled_at.replace(tzinfo=pytz.utc).astimezone(IST)
        ist_triggered_at = self.triggered_at.replace(tzinfo=pytz.utc).astimezone(IST) if self.triggered_at else None
        ist_email_opened_at = self.email_opened_at.replace(tzinfo=pytz.utc).astimezone(IST) if self.email_opened_at else None
        return {
            'type': self.sim_type,
            'target_group': self.target_group,
            'launch_date': ist_launch_date.strftime("%Y-%m-%d"),
            'completion_date': ist_completion_date.strftime("%Y-%m-%d"),
            'scheduled_at': ist_scheduled_at.strftime("%Y-%m-%d %H:%M:%S"),
            'triggered': self.triggered,
            'triggered_at': ist_triggered_at.strftime("%Y-%m-%d %H:%M:%S") if ist_triggered_at else None,
            'notification_email': self.notification_email,
            'email_opened': self.email_opened,
            'email_opened_at': ist_email_opened_at.strftime("%Y-%m-%d %H:%M:%S") if ist_email_opened_at else None
        }

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EmailOpen(db.Model):
    __tablename__ = 'email_opens'

    id = db.Column(db.Integer, primary_key=True)
    simulation_id = db.Column(db.Integer, db.ForeignKey('scheduled_simulations.id'), nullable=False)
    opened_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(500), nullable=True)

    # Relationship to ScheduledSimulation
    simulation = db.relationship('ScheduledSimulation', backref='email_opens')

    def to_dict(self):
        IST = pytz.timezone('Asia/Kolkata')
        ist_opened_at = self.opened_at.replace(tzinfo=pytz.utc).astimezone(IST)
        return {
            'id': self.id,
            'simulation_id': self.simulation_id,
            'opened_at': ist_opened_at.strftime("%Y-%m-%d %H:%M:%S"),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }

# Helper functions for prediction

def predict_fake_or_real_email_content(text):
    try:
        prompt = f"""
You are a cybersecurity expert skilled in detecting scam or fake messages.

Analyze the following text and classify it clearly as either:
- Real/Legitimate
- Scam/Fake

Provide your response in this exact format, using plain text only (no asterisks, bold, or bullet points):

Classification: <Real/Legitimate or Scam/Fake>
Reason: <Clear and concise explanation, professionally written, without using Markdown formatting>


Text: {text}

Return  the classification message along with reason.
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
Provide your response in **plain text only**, using this exact format:

Classification: <One of the four categories>  
Reason: <Give a clear, short reason for your classification. Always include a reason, even if it seems obvious. Do not use Markdown formatting (no asterisks, bold, or bullet points). Keep it professional and easy to understand.>


URL: {url}

"""
        response = model.generate_content(prompt)
        if response and hasattr(response, "text"):
            # Extract just the classification from the response
            response_text = response.text.strip().lower()
            # Look for the classification keywords
            if "benign" in response_text:
                return "benign"
            elif "phishing" in response_text:
                return "phishing"
            elif "malware" in response_text:
                return "malware"
            elif "defacement" in response_text:
                return "defacement"
            else:
                return "unknown"
        else:
            return "unknown"
    except Exception as e:
        logging.error(f"Error detecting URL: {e}")
        return "error"

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
        sim_result = SimulationResult(  # type: ignore
            sim_type=data.get('type'),
            outcome=data.get('outcome'),
            action=data.get('action'),
            timestamp=datetime.now(timezone.utc)
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

        # Email open statistics
        total_simulations_sent = ScheduledSimulation.query.filter_by(triggered=True).count()
        total_emails_opened = EmailOpen.query.count()
        open_rate = round((total_emails_opened / total_simulations_sent) * 100, 1) if total_simulations_sent > 0 else 0

        return jsonify({
            'total_simulations': total,
            'success_rate': success_rate,
            'most_recent': most_recent,
            'common_type': common_type,
            'total_emails_sent': total_simulations_sent,
            'total_emails_opened': total_emails_opened,
            'email_open_rate': open_rate
        })
    except Exception as e:
        logging.error(f"Error getting simulation stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/schedule_simulation', methods=['POST'])
@login_required
def schedule_simulation():
    try:
        data = request.json
        launch_date = datetime.strptime(data.get('launch_date'), "%Y-%m-%d").date()
        completion_date = datetime.strptime(data.get('completion_date'), "%Y-%m-%d").date()

        scheduled = ScheduledSimulation(
            user_id=current_user.id,
            sim_type=data.get('simulation_type'),
            target_group=data.get('target_group'),
            launch_date=launch_date,
            completion_date=completion_date,
            scheduled_at=datetime.now(timezone.utc),
            notification_email=data.get('notification_email')
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
@login_required
def get_scheduled_simulations():
    try:
        # Only show simulations for the current user
        scheduled = ScheduledSimulation.query.filter_by(user_id=current_user.id).order_by(ScheduledSimulation.launch_date.asc()).all()
        return jsonify([s.to_dict() for s in scheduled])
    except Exception as e:
        logging.error(f"Error getting scheduled simulations: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def send_email_notification(sim):
    try:
        # Get the user who created this simulation
        user = User.query.get(sim.user_id)
        if not user or not user.email:
            logging.warning(f"No email found for user {sim.user_id}")
            return
            
        # Check if email configuration is set
        if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
            logging.error("Email configuration is missing. Please check your environment variables.")
            return
        
        # Create tracking URLs
        tracking_pixel_url = f"http://127.0.0.1:5000/track_email_pixel/{sim.id}"
        manual_confirm_url = f"http://127.0.0.1:5000/track_email_open/{sim.id}"
        
        msg = Message(
            subject=f"Simulation Triggered: {sim.sim_type}",
            recipients=[sim.notification_email],
            body=f"""
Hello {user.username},

A scheduled simulation has been triggered.

Type: {sim.sim_type}
Target Group: {sim.target_group}
Launch Date: {sim.launch_date}
Completion Date: {sim.completion_date}
Triggered At: {sim.triggered_at}

To confirm you received this email, click here: {manual_confirm_url}

Best regards,
ThreatGuard Team
""",
            html=f"""
<html>
<body>
<p>Hello {user.username},</p>

<p>A scheduled simulation has been triggered.</p>

<p><strong>Type:</strong> {sim.sim_type}<br>
<strong>Target Group:</strong> {sim.target_group}<br>
<strong>Launch Date:</strong> {sim.launch_date}<br>
<strong>Completion Date:</strong> {sim.completion_date}<br>
<strong>Triggered At:</strong> {sim.triggered_at}</p>

<p><a href="{manual_confirm_url}" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirm Email Received</a></p>

<p>Best regards,<br>
ThreatGuard Team</p>

<!-- Tracking pixel - invisible image that tracks when email is opened -->
<img src="{tracking_pixel_url}" width="1" height="1" style="display:none;" alt="" />
</body>
</html>
"""
        )
        mail.send(msg)
        logging.info(f"Notification email sent to {sim.notification_email} for simulation {sim.id}")
    except Exception as e:
        logging.error(f"Error sending notification email: {e}")
        print(f"Email error details: {e}")

def trigger_due_simulations():
    try:
        with app.app_context():
            # Use timezone-aware datetime instead of deprecated utcnow()
            now = datetime.now(timezone.utc).date()
            print(f"Checking for due simulations on {now}")
            
            # Get all simulations to debug
            all_simulations = ScheduledSimulation.query.all()
            print(f"Total simulations in database: {len(all_simulations)}")
            
            for sim in all_simulations:
                print(f"Sim ID {sim.id}: launch_date={sim.launch_date}, triggered={sim.triggered}, notification_email={sim.notification_email}")
            
            due = ScheduledSimulation.query.filter(
                ScheduledSimulation.launch_date <= now,
                ~ScheduledSimulation.triggered
            ).all()
            
            print(f"Found {len(due)} due simulations")
            
            for sim in due:
                try:
                    print(f"Triggering simulation ID {sim.id}: {sim.sim_type} for {sim.target_group}")
                    sim.triggered = True
                    sim.triggered_at = datetime.now(timezone.utc)
                    db.session.commit()
                    logging.info(f"Triggered simulation: {sim.id} ({sim.sim_type}) for {sim.target_group}")
                    
                    # Send email notification
                    send_email_notification(sim)
                    print(f"✓ Email sent to {sim.notification_email}")
                    
                except Exception as e:
                    logging.error(f"Error processing simulation {sim.id}: {e}")
                    print(f"✗ Error processing simulation {sim.id}: {e}")
                    db.session.rollback()
                    
    except Exception as e:
        logging.error(f"Error in trigger_due_simulations: {e}")
        print(f"Scheduler error: {e}")

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
        username_or_email = request.form['username']
        password = request.form['password']
        
        # Try to find user by username first, then by email
        user = User.query.filter_by(username=username_or_email).first()
        if not user:
            user = User.query.filter_by(email=username_or_email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))  # Redirect to landing page
        else:
            return render_template('login.html', error='Invalid username/email or password')
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
        email = request.form['email']
        password = request.form['password']
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template('register.html', error='Please enter a valid email address.')
        
        if not is_valid_password(password):
            return render_template('register.html', error='Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/test_email')
@login_required
def test_email():
    """Test route to check if email configuration is working"""
    try:
        # Check email configuration
        email_config = {
            'MAIL_SERVER': app.config.get('MAIL_SERVER'),
            'MAIL_PORT': app.config.get('MAIL_PORT'),
            'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
            'MAIL_USERNAME': app.config.get('MAIL_USERNAME'),
            'MAIL_PASSWORD': '***' if app.config.get('MAIL_PASSWORD') else 'NOT SET',
            'MAIL_DEFAULT_SENDER': app.config.get('MAIL_DEFAULT_SENDER')
        }
        
        # Try to send a test email
        if current_user.email:
            msg = Message(
                subject="Test Email from ThreatGuard",
                recipients=[current_user.email],
                body=f"""
Hello {current_user.username},

This is a test email to verify that the email configuration is working correctly.

If you receive this email, the email system is properly configured.

Best regards,
ThreatGuard Team
"""
            )
            mail.send(msg)
            return jsonify({
                'status': 'success',
                'message': f'Test email sent to {current_user.email}',
                'config': email_config
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No email address found for current user',
                'config': email_config
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Email test failed: {str(e)}',
            'config': email_config
        })

@app.route('/trigger_test_simulation')
@login_required
def trigger_test_simulation():
    """Manually trigger a test simulation to test email notifications"""
    try:
        # Create a test simulation
        test_sim = ScheduledSimulation(
            user_id=current_user.id,
            sim_type="Test Phishing Simulation",
            target_group="Test Group",
            launch_date=datetime.now(timezone.utc).date(),
            completion_date=(datetime.now(timezone.utc) + timedelta(days=1)).date(),
            scheduled_at=datetime.now(timezone.utc),
            triggered=True,
            triggered_at=datetime.now(timezone.utc),
            notification_email=current_user.email
        )
        
        # Send email notification
        send_email_notification(test_sim)
        
        return jsonify({
            'status': 'success',
            'message': f'Test simulation triggered and email sent to {current_user.email}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Test simulation failed: {str(e)}'
        })

@app.route('/track_email_pixel/<int:simulation_id>')
def track_email_pixel(simulation_id):
    """Track email opens via invisible pixel"""
    try:
        # Get the simulation
        simulation = ScheduledSimulation.query.get(simulation_id)
        if not simulation:
            return "Not found", 404
        
        # Mark as opened if not already opened
        if not simulation.email_opened:
            simulation.email_opened = True
            simulation.email_opened_at = datetime.now(timezone.utc)
            
            # Add email open record
            email_open = EmailOpen(
                simulation_id=simulation_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(email_open)
            
            db.session.commit()
            logging.info(f"Email automatically marked as opened for simulation {simulation_id}")
        
        # Return a 1x1 transparent GIF pixel
        pixel_data = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        
        response = app.response_class(pixel_data, mimetype='image/gif')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logging.error(f"Error tracking email pixel: {e}")
        # Still return the pixel even if tracking fails
        pixel_data = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        return app.response_class(pixel_data, mimetype='image/gif')

@app.route('/track_email_open/<int:simulation_id>')
def track_email_open(simulation_id):
    try:
        # Get the simulation
        simulation = ScheduledSimulation.query.get(simulation_id)
        if not simulation:
            return "Simulation not found", 404
        
        # Record the email open
        email_open = EmailOpen(
            simulation_id=simulation_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(email_open)
        
        # Mark the simulation as email opened (if not already opened)
        if not simulation.email_opened:
            simulation.email_opened = True
            simulation.email_opened_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        # Return a confirmation page
        return f"""
        <html>
        <head>
            <title>Email Confirmed</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: #2ecc71; font-size: 24px; margin-bottom: 20px; }}
                .message {{ color: #333; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="success">✓ Email Confirmed!</div>
            <div class="message">
                Thank you for confirming receipt of the simulation notification.<br>
                Simulation ID: {simulation_id}<br>
                Type: {simulation.sim_type}<br>
                Confirmed at: {simulation.email_opened_at.strftime('%Y-%m-%d %H:%M:%S') if simulation.email_opened_at else 'Now'}
            </div>
        </body>
        </html>
        """
        
    except Exception as e:
        logging.error(f"Error tracking email open: {e}")
        return "Error processing confirmation", 500

@app.route('/test_mark_opened/<int:simulation_id>')
def test_mark_opened(simulation_id):
    """Test route to manually mark an email as opened"""
    try:
        # Get the simulation
        simulation = ScheduledSimulation.query.get(simulation_id)
        if not simulation:
            return f"Simulation {simulation_id} not found", 404
        
        # Mark as opened if not already opened
        if not simulation.email_opened:
            simulation.email_opened = True
            simulation.email_opened_at = datetime.now(timezone.utc)
            
            # Add email open record
            email_open = EmailOpen(
                simulation_id=simulation_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(email_open)
            
            db.session.commit()
            
            return f"""
            <html>
            <head><title>Email Marked as Opened</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h2 style="color: #2ecc71;">✓ Email Marked as Opened!</h2>
                <p>Simulation ID: {simulation_id}</p>
                <p>Type: {simulation.sim_type}</p>
                <p>Marked at: {simulation.email_opened_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><a href="javascript:window.close()">Close this window</a></p>
            </body>
            </html>
            """
        else:
            return f"""
            <html>
            <head><title>Already Opened</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h2 style="color: #f39c12;">Email Already Marked as Opened</h2>
                <p>Simulation ID: {simulation_id}</p>
                <p>Opened at: {simulation.email_opened_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><a href="javascript:window.close()">Close this window</a></p>
            </body>
            </html>
            """
        
    except Exception as e:
        logging.error(f"Error in test_mark_opened: {e}")
        return f"Error: {str(e)}", 500

@app.route('/mark_email_opened/<int:simulation_id>', methods=['POST'])
@login_required
def mark_email_opened(simulation_id):
    """Manually mark an email as opened"""
    try:
        # Get the simulation
        simulation = ScheduledSimulation.query.get(simulation_id)
        if not simulation:
            return jsonify({'status': 'error', 'message': 'Simulation not found'}), 404
        
        # Check if user has permission to modify this simulation
        if simulation.user_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        
        # Mark as opened if not already opened
        if not simulation.email_opened:
            simulation.email_opened = True
            simulation.email_opened_at = datetime.now(timezone.utc)
            
            # Add email open record
            email_open = EmailOpen(
                simulation_id=simulation_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(email_open)
            
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Email marked as opened for simulation {simulation_id}'
            })
        else:
            return jsonify({
                'status': 'info',
                'message': f'Email was already marked as opened for simulation {simulation_id}'
            })
        
    except Exception as e:
        logging.error(f"Error marking email as opened: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        # db.drop_all()  # Drop all tables to recreate with new schema
        db.create_all()  # Recreate tables
    app.run(debug=True)
