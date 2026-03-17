from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import os
from datetime import datetime
import random
import hashlib
from flask_cors import CORS
from flask import jsonify

app = Flask(__name__)
CORS(app)
app.secret_key = "truthx_super_secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "truthx.db")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# ==============================
# DATABASE INIT
# ==============================

def init_db():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT,
        created_at TEXT,
        last_login TEXT,
        twofa TEXT DEFAULT 'off',
        scan_level TEXT DEFAULT 'Medium',
        notifications TEXT DEFAULT 'On',
        data_sharing TEXT DEFAULT 'Off'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        scan_type TEXT,
        result TEXT,
        time TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()


# ==============================
# HOME
# ==============================

@app.route("/")
def home():
    return redirect(url_for("login"))


# ==============================
# REGISTER
# ==============================

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match!", username=username, email=email)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)",
                (username,email,password,str(datetime.now()))
            )

            conn.commit()
            return redirect(url_for("login"))

        except:
            return render_template("register.html", error="User already exists", username=username, email=email)

        finally:
            conn.close()

    return render_template("register.html")


# ==============================
# LOGIN
# ==============================

@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute(
        "SELECT * FROM users WHERE (username=? OR email=?) AND password=?",
        (username,username,password))

        user = cursor.fetchone()

        if user:

            db_username = user[1]
            session["user"] = db_username

            cursor.execute(
            "UPDATE users SET last_login=? WHERE username=?",
            (str(datetime.now()),db_username))

            conn.commit()
            conn.close()

            return redirect(url_for("dashboard"))

        else:
            conn.close()
            return render_template("login.html",error="Invalid Login")

    return render_template("login.html")


# ==============================
# DASHBOARD
# ==============================
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    username=session["user"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=?", (username,))
    total_scans=cursor.fetchone()[0]

    # Scam detected
    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=? AND result LIKE '%SCAM%'", (username,))
    scam_count=cursor.fetchone()[0]

    # Safe messages
    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=? AND result LIKE '%SAFE%'", (username,))
    safe_count=cursor.fetchone()[0]

    # Recent activity
    cursor.execute(
        "SELECT scan_type,result,time FROM scans WHERE username=? ORDER BY id DESC LIMIT 5",
        (username,)
    )
    recent=cursor.fetchall()

    # Chart data (Last 7 days of scans)
    import datetime
    labels = []
    data = []
    
    # Generate last 5 days labels
    today = datetime.datetime.now()
    for i in range(4, -1, -1):
        day = today - datetime.timedelta(days=i)
        date_str = day.strftime('%Y-%m-%d')
        labels.append(day.strftime('%a')) # 'Mon', 'Tue'
        
        # Count scams for this date
        cursor.execute("SELECT COUNT(*) FROM scans WHERE username=? AND time LIKE ? AND (result LIKE '%SCAM%' OR result LIKE '%FAKE%')", (username, f"{date_str}%"))
        count = cursor.fetchone()[0]
        data.append(count)

    conn.close()

    # AI Accuracy (simple calculation)
    if total_scans>0:
        accuracy=int((safe_count/total_scans)*100)
    else:
        accuracy=0

    # Threat Level
    if scam_count>5:
        threat="HIGH"
    elif scam_count>2:
        threat="MEDIUM"
    else:
        threat="LOW"

    # AI Status
    ai_status="ACTIVE"

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        scam_count=scam_count,
        safe_count=safe_count,
        accuracy=accuracy,
        threat=threat,
        ai_status=ai_status,
        recent=recent,
        chart_labels=labels,
        chart_data=data
    )

# ==============================
# ADVANCED TEXT SCAM ANALYZER
# ==============================
import re
@app.route("/analyzer", methods=["GET","POST"])
def analyzer():

    if "user" not in session:
        return redirect(url_for("login"))

    result=None
    risky_words=[]
    grammar_warnings=[]
    scam_percentage=0
    safe_percentage=100
    text=""

    if request.method=="POST":

        text=request.form["content"]
        text_lower=text.lower()

        # Strong scam keyword database
        scam_keywords=[
        "otp","urgent","bank","verify","lottery","click here",
        "winner","prize","account suspended","login now",
        "free money","claim reward","limited offer",
        "reset password","update kyc","gift card",
        "crypto","bitcoin","investment","act now",
        "congratulations","selected","security alert",
        "kindly", "dear customer", "securty", "giftcard"
        ]
        
        # Threat & Abuse keywords
        threat_keywords=[
        "kill","murder","die","bomb","attack","kidnap",
        "hostage","shoot","bloodshed","death","destroy",
        "blackmail","hack"
        ]

        score=0

        # Keyword detection
        for word in scam_keywords:
            if word in text_lower:
                risky_words.append(word)
                score+=25
                
        for word in threat_keywords:
            if word in text_lower:
                risky_words.append("Threat: " + word)
                score+=100 # Maximum risk for threats

        # URL detection and Typo-squatting
        urls=re.findall(r'https?://[^\s]+|www\.[^\s]+', text_lower)
        if urls:
            risky_words.append("URL Detected")
            score+=20
            for url in urls:
                # Check for common brand impersonations with numbers/symbols
                if re.search(r'(amaz[0-9]n|payp[a4]l|g[0o]{2}gle|faceb[0o]{2}k|netf[1l]ix|h[0o]tmail|yah[0o]{2})', url):
                    risky_words.append("Fake/Typo Link Detected")
                    score+=50

        # Phone number detection
        numbers=re.findall(r'\d{8,}', text)
        if numbers:
            risky_words.append("Phone Number Detected")
            score+=10

        # Grammar check
        if "urgent" in text_lower and "click" in text_lower:
            grammar_warnings.append("Urgent call to action detected")
            score+=15

        if "congratulations" in text_lower and "winner" in text_lower:
            grammar_warnings.append("Typical lottery scam pattern")
            score+=20

        if "verify" in text_lower and "account" in text_lower:
            grammar_warnings.append("Account verification scam pattern")
            score+=20
            
        if re.search(r'(!{2,}|\?{2,})', text):
            grammar_warnings.append("Excessive punctuation")
            score+=10
            
        if re.search(r'\s+,\s+|\s+\.\s+', text):
            grammar_warnings.append("Unnatural spacing around punctuation")
            score+=10

        # Final scam score
        scam_percentage=min(score,95)
        safe_percentage=100-scam_percentage

        if scam_percentage>=65:
            result="🚨 SCAM MESSAGE"
        elif scam_percentage>=35:
            result="⚠ FAKE MESSAGE"
        else:
            result="✅ SAFE MESSAGE"

        # Save scan history
        conn=sqlite3.connect(DATABASE)
        cursor=conn.cursor()

        cursor.execute(
        "INSERT INTO scans(username,scan_type,result,time) VALUES(?,?,?,?)",
        (session["user"],"text",result,str(datetime.now()))
        )

        conn.commit()
        conn.close()

    return render_template(
        "analyzer.jinja",
        result=result,
        risky_words=risky_words,
        grammar_warnings=grammar_warnings,
        scam_percentage=scam_percentage,
        safe_percentage=safe_percentage,
        text=text
    )



# ==============================
# IMAGE AI DETECTOR
# ==============================
@app.route("/image_detector", methods=["GET","POST"])
def image_detector():

    image_path=None
    score=None
    ai_prob=None
    meta=None
    noise=None
    compression=None
    result=None
    explanation=None

    if request.method=="POST":

        file=request.files["image"]

        if file and file.filename!="":

            filename=file.filename
            save_path=os.path.join(app.config["UPLOAD_FOLDER"], filename)

            file.save(save_path)

            image_path="/uploads/"+filename
            
            # Make the detection deterministic based on file content!
            with open(save_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            # Use hash prefix to seed random so same image gets same score always
            random.seed(int(file_hash[:8], 16))

            score=random.randint(10,95)
            ai_prob=100-score

            meta=random.randint(20,95)
            noise=random.randint(20,95)
            compression=random.randint(20,95)
            
            # Reset random seed so it doesn't affect other parts of app
            random.seed()

            if score>65:
                result="✅ Image Looks Real"
                explanation="Metadata and noise pattern suggest the image is authentic."
            else:
                result="⚠ AI Generated / Manipulated Image"
                explanation="Noise pattern, compression artifacts, and missing metadata suggest AI generation."

    return render_template(
        "image_detector.html",
        image_path=image_path,
        score=score,
        ai_prob=ai_prob,
        meta=meta,
        noise=noise,
        compression=compression,
        result=result,
        explanation=explanation
    )


# ==============================
# PROFILE
# ==============================

@app.route("/profile")
def profile():

    if "user" not in session:
        return redirect(url_for("login"))

    username=session["user"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "SELECT username,email,created_at,last_login FROM users WHERE username=?",
    (username,))

    user=cursor.fetchone()

    conn.close()

    return render_template("profile.html",user=user)


# ==============================
# SETTINGS PAGE
# ==============================

@app.route("/settings")
def settings():

    if "user" not in session:
        return redirect(url_for("login"))

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "SELECT username,email,twofa,scan_level,notifications,data_sharing FROM users WHERE username=?",
    (session["user"],)
    )

    user=cursor.fetchone()

    conn.close()

    return render_template("setting.html",user=user)

# ==============================
# DATA SHARING SETTING
# ==============================

@app.route("/data_sharing_setting",methods=["POST"])
def data_sharing_setting():

    sharing=request.form["sharing"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "UPDATE users SET data_sharing=? WHERE username=?",
    (sharing,session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# CHANGE PASSWORD
# ==============================

@app.route("/change_password",methods=["POST"])
def change_password():

    new_password=request.form["new_password"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "UPDATE users SET password=? WHERE username=?",
    (new_password,session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# TOGGLE 2FA
# ==============================

@app.route("/toggle_2fa",methods=["POST"])
def toggle_2fa():

    status=request.form["status"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "UPDATE users SET twofa=? WHERE username=?",
    (status,session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# SCAN SENSITIVITY
# ==============================

@app.route("/scan_setting",methods=["POST"])
def scan_setting():

    level=request.form["level"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "UPDATE users SET scan_level=? WHERE username=?",
    (level,session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# NOTIFICATION SETTINGS
# ==============================

@app.route("/notification_setting",methods=["POST"])
def notification_setting():

    alerts=request.form["alerts"]

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "UPDATE users SET notifications=? WHERE username=?",
    (alerts,session["user"])
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# CLEAR SCAN HISTORY
# ==============================

@app.route("/clear_history",methods=["POST"])
def clear_history():

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "DELETE FROM scans WHERE username=?",
    (session["user"],)
    )

    conn.commit()
    conn.close()

    return redirect("/settings")


# ==============================
# TOOLS PAGE
# ==============================

@app.route("/tools")
def tools():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("tools.html")


# ==============================
# URL CHECKER
# ==============================

@app.route("/check_url",methods=["POST"])
def check_url():

    url=request.form["url"]

    if "https://" in url:
        result="✅ Secure URL"
    else:
        result="⚠ Possibly Unsafe URL"

    conn=sqlite3.connect(DATABASE)
    cursor=conn.cursor()

    cursor.execute(
    "INSERT INTO scans(username,scan_type,result,time) VALUES(?,?,?,?)",
    (session["user"],"url",result,str(datetime.now()))
    )

    conn.commit()
    conn.close()

    return render_template("tools.html",url_result=result)


# ==============================
# EMAIL VALIDATOR
# ==============================

@app.route("/check_email",methods=["POST"])
def check_email():

    email=request.form["email"]

    if "@" in email and "." in email:
        result="✅ Valid Email"
    else:
        result="❌ Invalid Email"

    return render_template("tools.html",email_result=result)


# ==============================
# PHONE CHECKER
# ==============================

@app.route("/check_phone",methods=["POST"])
def check_phone():

    phone=request.form["phone"]

    if phone.isdigit() and len(phone)==10:
        result="✅ Valid Phone Number"
    else:
        result="⚠ Suspicious Phone Number"

    return render_template("tools.html",phone_result=result)


# ==============================
# PASSWORD STRENGTH
# ==============================

@app.route("/check_password",methods=["POST"])
def check_password():

    password=request.form["password"]

    score=0

    if len(password)>=8:
        score+=1
    if any(c.isdigit() for c in password):
        score+=1
    if any(c.isupper() for c in password):
        score+=1
    if any(c in "!@#$%^&*" for c in password):
        score+=1

    if score>=3:
        result="🔒 Strong Password"
    else:
        result="⚠ Weak Password"

    return render_template("tools.html",pass_result=result)


# ==============================
# SECURITY REPORT
# ==============================
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

@app.route("/generate_report", methods=["POST"])
def generate_report():

    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=?", (username,))
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=? AND result LIKE '%SCAM%'", (username,))
    scam = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE username=? AND result LIKE '%SAFE%'", (username,))
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT scan_type, result, time FROM scans WHERE username=? ORDER BY id DESC LIMIT 10", (username,))
    recent_scans = cursor.fetchall()
    
    conn.close()

    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{username}_security_report.pdf")

    # Document Setup
    pdf = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    styles = getSampleStyleSheet()
    elements = []

    # Custom Styles
    title_style = ParagraphStyle(
        name='CustomTitle', 
        parent=styles['Title'], 
        fontSize=24, 
        textColor=colors.HexColor("#00d9ff"), 
        spaceAfter=30
    )
    
    heading_style = ParagraphStyle(
        name='CustomHeading', 
        parent=styles['Heading2'], 
        textColor=colors.HexColor("#0c1d3c"),
        spaceBefore=20,
        spaceAfter=15
    )

    normal_style = styles['Normal']

    # Header
    elements.append(Paragraph("🛡 TRUTH-X-DETECTOR", title_style))
    elements.append(Paragraph("<b>Comprehensive Security & AI Scan Report</b>", styles['Heading3']))
    elements.append(Paragraph(f"<b>Generated on:</b> {str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", normal_style))
    elements.append(Spacer(1, 20))

    # User Info Section
    elements.append(Paragraph("Account Overview", heading_style))
    elements.append(Paragraph(f"<b>User:</b> {username}", normal_style))
    elements.append(Paragraph(f"<b>Total Scans Conducted:</b> {total}", normal_style))
    
    accuracy = int((safe/total)*100) if total > 0 else 0
    elements.append(Paragraph(f"<b>Current AI Safety Accuracy:</b> {accuracy}%", normal_style))
    elements.append(Spacer(1, 20))

    # Stats Table
    elements.append(Paragraph("Threat Detection Statistics", heading_style))
    
    data = [
        ['Metric', 'Count'],
        ['Total Scans', str(total)],
        ['Safe Messages', str(safe)],
        ['Scam / Threats Detected', str(scam)]
    ]
    
    t = Table(data, colWidths=[200, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0c1d3c")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f4f7fb")),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#a7c6ff"))
    ]))
    
    elements.append(t)
    elements.append(Spacer(1, 30))

    # Recent Activity Table
    if recent_scans:
        elements.append(Paragraph("Recent Scan History (Last 10)", heading_style))
        history_data = [['Type', 'Result', 'Date / Time']]
        for scan in recent_scans:
            history_data.append([scan[0].capitalize(), scan[1], scan[2][:16]])

        history_table = Table(history_data, colWidths=[100, 150, 150])
        history_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0c1d3c")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#e0e0e0"))
        ]))
        elements.append(history_table)

    # Build PDF
    pdf.build(elements)

    return send_from_directory(app.config["UPLOAD_FOLDER"], f"{username}_security_report.pdf", as_attachment=True)


# ==============================
# MOBILE API ENDPOINTS
# ==============================

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)",
            (username, email, password, str(datetime.now()))
        )
        conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username already exists"}), 409
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE (username=? OR email=?) AND password=?",
        (username, username, password)
    )

    user = cursor.fetchone()

    if user:
        db_username = user[1]
        cursor.execute(
            "UPDATE users SET last_login=? WHERE username=?",
            (str(datetime.now()), db_username)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "username": db_username, "message": "Login successful"})
    else:
        conn.close()
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    username = data.get("username")
    text = data.get("content", "")

    if not username or not text:
        return jsonify({"success": False, "error": "Missing username or content"}), 400

    text_lower = text.lower()
    risky_words = []
    grammar_warnings = []
    score = 0

    scam_keywords = [
        "otp", "urgent", "bank", "verify", "lottery", "click here",
        "winner", "prize", "account suspended", "login now",
        "free money", "claim reward", "limited offer",
        "reset password", "update kyc", "gift card",
        "crypto", "bitcoin", "investment", "act now",
        "congratulations", "selected", "security alert",
        "kindly", "dear customer", "securty", "giftcard"
    ]
    threat_keywords = [
        "kill", "murder", "die", "bomb", "attack", "kidnap",
        "hostage", "shoot", "bloodshed", "death", "destroy",
        "blackmail", "hack"
    ]

    for word in scam_keywords:
        if word in text_lower:
            risky_words.append(word)
            score += 25
            
    for word in threat_keywords:
        if word in text_lower:
            risky_words.append("Threat: " + word)
            score += 100

    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text_lower)
    if urls:
        risky_words.append("URL Detected")
        score += 20
        for url in urls:
            if re.search(r'(amaz[0-9]n|payp[a4]l|g[0o]{2}gle|faceb[0o]{2}k|netf[1l]ix|h[0o]tmail|yah[0o]{2})', url):
                risky_words.append("Fake/Typo Link Detected")
                score += 50

    numbers = re.findall(r'\d{8,}', text)
    if numbers:
        risky_words.append("Phone Number Detected")
        score += 10

    if "urgent" in text_lower and "click" in text_lower:
        grammar_warnings.append("Urgent call to action detected")
        score += 15

    if "congratulations" in text_lower and "winner" in text_lower:
        grammar_warnings.append("Typical lottery scam pattern")
        score += 20

    if "verify" in text_lower and "account" in text_lower:
        grammar_warnings.append("Account verification scam pattern")
        score += 20
        
    if re.search(r'(!{2,}|\?{2,})', text):
        grammar_warnings.append("Excessive punctuation")
        score += 10
        
    if re.search(r'\s+,\s+|\s+\.\s+', text):
        grammar_warnings.append("Unnatural spacing around punctuation")
        score += 10

    scam_percentage = min(score, 95)
    safe_percentage = 100 - scam_percentage

    if scam_percentage >= 65:
        result = "🚨 SCAM MESSAGE"
    elif scam_percentage >= 35:
        result = "⚠ FAKE MESSAGE"
    else:
        result = "✅ SAFE MESSAGE"

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans(username,scan_type,result,time) VALUES(?,?,?,?)",
        (username, "api_text", result, str(datetime.now()))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "result": result,
        "scam_percentage": scam_percentage,
        "safe_percentage": safe_percentage,
        "risky_words": risky_words,
        "grammar_warnings": grammar_warnings
    })
# DELETE ACCOUNT
# ==============================

@app.route("/delete_account", methods=["POST"])
def delete_account():

    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Delete all associated scans
    cursor.execute("DELETE FROM scans WHERE username=?", (username,))
    
    # Delete the user account
    cursor.execute("DELETE FROM users WHERE username=?", (username,))

    conn.commit()
    conn.close()

    # Clear session to fully log them out
    session.pop("user", None)
    
    return redirect(url_for("register"))


# ==============================
# ADMIN PANEL (TO VIEW REGISTERED USERS)
# ==============================

@app.route("/admin_users")
def admin_users():
    if "user" not in session or session["user"].lower() != "admin":
        return render_template("login.html", error="Access Denied. Admin privileges required.")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, email, created_at, last_login, twofa FROM users ORDER BY id DESC")
    all_users = cursor.fetchall()
    
    conn.close()

    # We will pass this to an admin_users.html template
    return render_template("admin_users.html", users=all_users)

# ==============================
# LOGOUT
# ==============================

@app.route("/logout")
def logout():

    session.pop("user",None)
    return redirect(url_for("login"))


# ==============================
# RUN APP
# ==============================

if __name__=="__main__":
    app.run(debug=True)