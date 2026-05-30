import streamlit as st
import pandas as pd
import joblib
import os
import sqlite3
import hashlib
import datetime
import plotly.graph_objects as go

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Fraud Shield", layout="wide")

MODEL_PATH = "online_fraud_detection_model_.pkl"
COLS_PATH = "model_columns.pkl"
DB_PATH = "fraud_app.db"

# ---------------- DATABASE ----------------
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT)""")

c.execute("""CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    amount REAL,
    risk REAL,
    decision TEXT,
    timestamp TEXT)""")

c.execute("""CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    risk REAL,
    message TEXT,
    timestamp TEXT)""")

conn.commit()

# ---------------- AUTH ----------------
def hash_pass(p):
    return hashlib.sha256(p.encode()).hexdigest()

# Default admin
c.execute("SELECT * FROM users WHERE username='admin'")
if not c.fetchone():
    c.execute("INSERT INTO users VALUES (?, ?, ?)",
              ("admin", hash_pass("admin123"), "admin"))
    conn.commit()

# ---------------- LOAD MODEL ----------------
if not os.path.exists(MODEL_PATH) or not os.path.exists(COLS_PATH):
    st.error("❌ Model or column file missing")
    st.stop()

model = joblib.load(MODEL_PATH)
model_cols = joblib.load(COLS_PATH)

# ---------------- SESSION ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = ""
    st.session_state.role = ""

# ---------------- LOGIN ----------------
def login():
    st.title("🔐 Fraud Shield Login")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        c.execute("SELECT * FROM users WHERE username=?", (u,))
        data = c.fetchone()

        if data and data[1] == hash_pass(p):
            st.session_state.logged_in = True
            st.session_state.user = u
            st.session_state.role = data[2]
            st.rerun()
        else:
            st.error("Invalid credentials")

# ---------------- CREATE USER ----------------
def create_user():
    st.subheader("🧑‍💼 Create User")

    u = st.text_input("New Username")
    p = st.text_input("New Password", type="password")
    role = st.selectbox("Role", ["user", "admin"])

    if st.button("Create User"):
        c.execute("SELECT * FROM users WHERE username=?", (u,))
        if c.fetchone():
            st.warning("User exists")
        else:
            c.execute("INSERT INTO users VALUES (?, ?, ?)",
                      (u, hash_pass(p), role))
            conn.commit()
            st.success("User created")

# ---------------- LOGGING ----------------
def log_txn(user, amount, risk, decision):
    c.execute("""INSERT INTO transactions 
        (username, amount, risk, decision, timestamp)
        VALUES (?, ?, ?, ?, ?)""",
        (user, amount, risk, decision, str(datetime.datetime.now())))
    conn.commit()

def create_alert(user, risk):
    c.execute("""INSERT INTO alerts 
        (username, risk, message, timestamp)
        VALUES (?, ?, ?, ?)""",
        (user, risk, "High Risk Fraud", str(datetime.datetime.now())))
    conn.commit()

# ---------------- RISK SCORE ----------------
def calculate_risk_score(proba, amount_ratio, high_ip,
                         high_txn, location, device,
                         intl, rule):

    score = proba * 60
    score += min(amount_ratio * 5, 20)
    score += high_ip * 10
    score += high_txn * 10
    score += location * 5
    score += device * 5
    score += intl * 5

    if rule:
        score += 20

    return min(int(score), 100)

# ---------------- GAUGE ----------------
def show_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': "Risk Score"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "black"},
            'steps': [
                {'range': [0, 40], 'color': "green"},
                {'range': [40, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "red"},
            ],
        }
    ))
    st.plotly_chart(fig, use_container_width=True)

# ---------------- MAIN APP ----------------
def app():

    st.sidebar.title("🛡️ Fraud Shield")
    st.sidebar.write(st.session_state.user)

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    tab1, tab2 = st.tabs(["🔍 Detection", "📊 Dashboard"])

    # ========================================================
    # DETECTION TAB
    # ========================================================
    with tab1:

        st.subheader("Transaction Analysis")

        auth = st.selectbox("Authentication", ["OTP", "PIN", "NONE"])

        amount = st.number_input("Amount", 0.0, value=5000.0)
        avg_amount = st.number_input("Avg Amount", 0.0, value=3000.0)
        txn_count = st.number_input("Txn Count", 0, value=1)

        ip_risk = st.slider("IP Risk", 0.0, 1.0, 0.2)

        device = st.selectbox("Device Change", ["No", "Yes"])
        location = st.selectbox("Location Change", ["No", "Yes"])
        intl = st.selectbox("International", ["No", "Yes"])

        device = 1 if device == "Yes" else 0
        location = 1 if location == "Yes" else 0
        intl = 1 if intl == "Yes" else 0

        # ---------------- FEATURES ----------------
        amount_ratio = amount / (avg_amount + 1)
        high_amount = int(amount_ratio > 3)
        high_ip = int(ip_risk > 0.7)
        high_txn = int(txn_count > 5)

        risk_score = (
            2*high_amount + 2*high_ip + 2*high_txn +
            location + intl + device
        )

        input_data = pd.DataFrame([{
            'amount': amount,
            'avg_amount_last_24h': avg_amount,
            'txn_count_last_24h': txn_count,
            'ip_address_risk_score': ip_risk,
            'device_change_flag': device,
            'location_change_flag': location,
            'is_international': intl,
            'high_amount': high_amount,
            'high_ip_risk': high_ip,
            'high_txn_velocity': high_txn,
            'risk_score': risk_score,
            'hour_of_day': 12,
            'day_of_week': 2,
            'is_weekend': 0,
            'hour': 12,
            'day': 1,
            'month': 1
        }])

        for m in ["OTP", "PIN", "NONE"]:
            input_data[f"authentication_method_{m}"] = 1 if auth == m else 0

        input_data = input_data.reindex(columns=model_cols, fill_value=0)

        # ========================================================
        # PREDICTION
        # ========================================================
        if st.button("Analyze Transaction"):

            proba = model.predict_proba(input_data)[0][1]

            # RULE ENGINE
            rule = False
            risk_signals = location + device + intl + high_ip + high_txn

            if amount_ratio > 10 and risk_signals >= 2:
                rule = True
            elif amount_ratio > 20:
                rule = True
            elif amount > 1000000:
                rule = True

            # DECISION
            if rule:
                st.error("🔴 HIGH RISK → BLOCK (Rule Override)")
                decision = "BLOCK"
                create_alert(st.session_state.user, proba)

            elif proba > 0.7:
                st.error(f"🔴 HIGH RISK → BLOCK ({proba:.2f})")
                decision = "BLOCK"

            elif proba > 0.3:
                st.warning(f"🟡 MEDIUM → OTP ({proba:.2f})")
                decision = "OTP"

            else:
                st.success(f"🟢 LOW → ALLOW ({proba:.2f})")
                decision = "ALLOW"

            # RISK SCORE
            score = calculate_risk_score(
                proba, amount_ratio, high_ip,
                high_txn, location, device, intl, rule
            )

            st.metric("Fraud Probability", f"{proba*100:.2f}%")
            show_gauge(score)

            # ========================================================
            # 🔍 FIXED EXPLANATION LOGIC
            # ========================================================
            st.subheader("🔍 Transaction Explanation")

            reasons = []

            if high_amount:
                reasons.append("Unusual amount vs behavior")
            if location:
                reasons.append("Location change")
            if device:
                reasons.append("New device")
            if intl:
                reasons.append("International transaction")
            if high_ip:
                reasons.append("Suspicious IP")
            if rule:
                reasons.append("Rule engine triggered")

            # -------- SAFE VS RISKY --------
            if decision in ["BLOCK", "OTP"]:

                st.markdown("### 🚨 Why this transaction is risky:")

                if reasons:
                    for r in reasons:
                        st.write("•", r)
                else:
                    st.write("• Model detected abnormal pattern")

            else:

                st.markdown("### ✅ Why this transaction is safe:")

                safe = []

                if not high_amount:
                    safe.append("Normal transaction amount")
                if not location:
                    safe.append("No location change")
                if not device:
                    safe.append("Known device")
                if not intl:
                    safe.append("Domestic transaction")
                if not high_ip:
                    safe.append("Trusted IP")

                for s in safe:
                    st.write("•", s)

            log_txn(st.session_state.user, amount, proba, decision)

    # ========================================================
    # DASHBOARD
    # ========================================================
    with tab2:

        if st.session_state.role == "admin":

            st.subheader("📊 Transactions")
            df = pd.read_sql("SELECT * FROM transactions", conn)
            st.dataframe(df)

            if not df.empty:
                st.bar_chart(df['decision'].value_counts())

            st.subheader("🚨 Alerts")
            alerts = pd.read_sql("SELECT * FROM alerts", conn)
            st.dataframe(alerts)

            create_user()

        else:
            st.warning("Admin only access")

# ---------------- RUN ----------------
if not st.session_state.logged_in:
    login()
else:
    app()
