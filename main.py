from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import os
import json
import uuid
import time
import random
import string
import subprocess
import threading
import shutil
import secrets
import platform
import socket
import hashlib
import hmac
import re
import requests
import zipfile
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'host_x_server_super_secret_key_2024')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.permanent_session_lifetime = timedelta(hours=24)

# ========== SECURITY SETTINGS ==========
BANNED_IPS_FILE = 'banned_ips.json'
RATE_LIMIT_FILE = 'rate_limits.json'
BRUTE_FORCE_FILE = 'brute_force.json'
BLOCKED_COUNTRIES_FILE = 'blocked_countries.json'

RATE_LIMIT_REQUESTS = 200
RATE_LIMIT_WINDOW = 60
BAN_DURATION_HOURS = 24
BRUTE_FORCE_ATTEMPTS = 10
DDOS_THRESHOLD = 50

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ========== JSON SAFE FUNCTIONS ==========
def safe_load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}
            data = json.loads(content)
            return data if isinstance(data, dict) else {}
    except:
        return {}

def save_json_safe(filepath, data):
    try:
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except:
        return False

# ========== BAN FUNCTIONS ==========
def load_banned_ips():
    return safe_load_json(os.path.join(BASE_DIR, BANNED_IPS_FILE))

def save_banned_ips(banned):
    return save_json_safe(os.path.join(BASE_DIR, BANNED_IPS_FILE), banned)

def load_rate_limits():
    return safe_load_json(os.path.join(BASE_DIR, RATE_LIMIT_FILE))

def save_rate_limits(limits):
    return save_json_safe(os.path.join(BASE_DIR, RATE_LIMIT_FILE), limits)

def is_ip_banned(ip):
    banned = load_banned_ips()
    if ip in banned:
        try:
            ban_until = datetime.fromisoformat(banned[ip])
            if datetime.now() < ban_until:
                return True
            else:
                del banned[ip]
                save_banned_ips(banned)
        except:
            if ip in banned:
                del banned[ip]
                save_banned_ips(banned)
    return False

def ban_ip(ip, reason="Suspicious activity detected"):
    banned = load_banned_ips()
    ban_until = datetime.now() + timedelta(hours=BAN_DURATION_HOURS)
    banned[ip] = ban_until.isoformat()
    save_banned_ips(banned)
    print(f"[SECURITY] IP {ip} banned - Reason: {reason}")
    limits = load_rate_limits()
    if ip in limits:
        del limits[ip]
        save_rate_limits(limits)
    log_security_event('ip_banned', ip, request.remote_addr if hasattr(request, 'remote_addr') else 'system', reason, 'high')

def rate_limit_check(ip):
    limits = load_rate_limits()
    now = time.time()
    if ip not in limits:
        limits[ip] = {'count': 1, 'window_start': now, 'last_requests': []}
        save_rate_limits(limits)
        return True
    data = limits[ip]
    if now - data['window_start'] > RATE_LIMIT_WINDOW:
        data['count'] = 1
        data['window_start'] = now
        data['last_requests'] = []
        save_rate_limits(limits)
        return True
    data['count'] += 1
    if 'last_requests' not in data:
        data['last_requests'] = []
    data['last_requests'].append(now)
    data['last_requests'] = data['last_requests'][-30:]
    recent_requests = [t for t in data['last_requests'] if now - t <= 5]
    if len(recent_requests) >= DDOS_THRESHOLD:
        ban_ip(ip, f"DDoS attack detected")
        return False
    if data['count'] > RATE_LIMIT_REQUESTS * 3:
        ban_ip(ip, f"Extreme rate limit exceeded")
        return False
    save_rate_limits(limits)
    return True

def detect_ddos_behavior(ip, endpoint):
    limits = load_rate_limits()
    now = time.time()
    if ip not in limits:
        return False
    data = limits[ip]
    if 'last_requests' not in data:
        data['last_requests'] = []
    data['last_requests'].append(now)
    data['last_requests'] = data['last_requests'][-20:]
    recent = [t for t in data['last_requests'] if now - t <= 5]
    if len(recent) >= DDOS_THRESHOLD:
        ban_ip(ip, f"DDoS pattern detected")
        return True
    save_rate_limits(limits)
    return False

# ========== BRUTE FORCE PROTECTION ==========
def load_brute_force():
    return safe_load_json(os.path.join(BASE_DIR, BRUTE_FORCE_FILE))

def save_brute_force(data):
    return save_json_safe(os.path.join(BASE_DIR, BRUTE_FORCE_FILE), data)

def check_brute_force(ip, username):
    bf_data = load_brute_force()
    key = f"{ip}_{username}"
    if key in bf_data:
        attempts = bf_data[key]['attempts']
        last_attempt = datetime.fromisoformat(bf_data[key]['last_attempt'])
        if attempts >= BRUTE_FORCE_ATTEMPTS and (datetime.now() - last_attempt).seconds < 1800:
            remaining = 30 - ((datetime.now() - last_attempt).seconds // 60)
            return False, f"Too many failed attempts. Try again in {remaining} minutes"
        if (datetime.now() - last_attempt).seconds >= 1800:
            del bf_data[key]
            save_brute_force(bf_data)
    return True, ""

@app.route('/refresh_captcha')
def refresh_captcha():
    new_captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = new_captcha
    return jsonify({"captcha": new_captcha})

def record_failed_attempt(ip, username):
    bf_data = load_brute_force()
    key = f"{ip}_{username}"
    if key not in bf_data:
        bf_data[key] = {'attempts': 0, 'last_attempt': datetime.now().isoformat()}
    bf_data[key]['attempts'] += 1
    bf_data[key]['last_attempt'] = datetime.now().isoformat()
    save_brute_force(bf_data)
    log_security_event('failed_login', ip, username, f'Failed login attempt for {username}', 'medium')

# ========== CSRF PROTECTION ==========
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    return token and token == session.get('csrf_token')

# ========== SESSION FIXATION PROTECTION ==========
def regenerate_session():
    old_user = session.get('user')
    old_role = session.get('role')
    old_csrf = session.get('csrf_token')
    session.clear()
    if old_user:
        session['user'] = old_user
    if old_role:
        session['role'] = old_role
    if old_csrf:
        session['csrf_token'] = old_csrf
    session['fingerprint'] = hmac.new(
        app.secret_key.encode(),
        f"{request.remote_addr}|{request.user_agent.string}".encode(),
        hashlib.sha256
    ).hexdigest()

def validate_session_fingerprint():
    if 'fingerprint' not in session:
        return True
    expected = hmac.new(
        app.secret_key.encode(),
        f"{request.remote_addr}|{request.user_agent.string}".encode(),
        hashlib.sha256
    ).hexdigest()
    return session.get('fingerprint') == expected

# ========== GEOIP BLOCKING ==========
def load_blocked_countries():
    return safe_load_json(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE))

def save_blocked_countries(data):
    return save_json_safe(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE), data)

def get_country_from_ip(ip):
    try:
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return 'Local'
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return data.get('countryCode', 'Unknown')
        return 'Unknown'
    except:
        return 'Unknown'

def country_block_check(ip):
    try:
        if not os.path.exists(os.path.join(BASE_DIR, BLOCKED_COUNTRIES_FILE)):
            return True, ""
        blocked_countries = load_blocked_countries()
        if not blocked_countries or 'blocked' not in blocked_countries:
            return True, ""
        country = get_country_from_ip(ip)
        if country == 'Local':
            return True, ""
        if country in blocked_countries.get('blocked', []):
            return False, f"Access from {country} is blocked"
        return True, ""
    except:
        return True, ""

# ========== IP DETECTION FUNCTIONS ==========
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        if ip and ip != '127.0.0.1' and ip != '::1':
            return ip
    
    if request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
        if ip and ip != '127.0.0.1' and ip != '::1':
            return ip
    
    ip = request.remote_addr
    
    if ip in ['127.0.0.1', '::1', 'localhost']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            pass
    
    return ip

def parse_user_agent_advanced(user_agent_string):
    user_agent_string = user_agent_string or ''
    user_agent_lower = user_agent_string.lower()
    
    device_info = {
        'browser': 'Unknown',
        'browser_version': 'Unknown',
        'os': 'Unknown',
        'os_version': 'Unknown',
        'device_type': 'Desktop',
        'device_name': 'Unknown',
        'device_brand': 'Unknown',
        'is_mobile': False,
        'is_tablet': False,
        'is_bot': False
    }
    
    if 'bot' in user_agent_lower or 'crawler' in user_agent_lower or 'spider' in user_agent_lower:
        device_info['is_bot'] = True
        device_info['device_name'] = 'Bot/Crawler'
        return device_info
    
    mobile_keywords = ['mobile', 'iphone', 'android', 'blackberry', 'windows phone', 'opera mini', 'iemobile']
    tablet_keywords = ['ipad', 'tablet', 'kindle', 'playbook', 'silk']
    
    for keyword in mobile_keywords:
        if keyword in user_agent_lower:
            device_info['is_mobile'] = True
            device_info['device_type'] = 'Mobile'
            break
    
    for keyword in tablet_keywords:
        if keyword in user_agent_lower:
            device_info['is_tablet'] = True
            device_info['device_type'] = 'Tablet'
            device_info['is_mobile'] = False
            break
    
    if 'chrome' in user_agent_lower and 'edg' not in user_agent_lower and 'opr' not in user_agent_lower:
        device_info['browser'] = 'Chrome'
        match = re.search(r'chrome/(\d+)', user_agent_lower)
        if match:
            device_info['browser_version'] = match.group(1)
    elif 'firefox' in user_agent_lower:
        device_info['browser'] = 'Firefox'
        match = re.search(r'firefox/(\d+)', user_agent_lower)
        if match:
            device_info['browser_version'] = match.group(1)
    elif 'safari' in user_agent_lower and 'chrome' not in user_agent_lower:
        device_info['browser'] = 'Safari'
    elif 'edg' in user_agent_lower:
        device_info['browser'] = 'Edge'
    elif 'opr' in user_agent_lower or 'opera' in user_agent_lower:
        device_info['browser'] = 'Opera'
    elif 'msie' in user_agent_lower or 'trident' in user_agent_lower:
        device_info['browser'] = 'Internet Explorer'
    
    if 'android' in user_agent_lower:
        device_info['os'] = 'Android'
        match = re.search(r'android (\d+)', user_agent_lower)
        if match:
            device_info['os_version'] = match.group(1)
        
        if 'samsung' in user_agent_lower:
            device_info['device_brand'] = 'Samsung'
            device_info['device_name'] = 'Samsung Galaxy'
        elif 'xiaomi' in user_agent_lower or 'redmi' in user_agent_lower:
            device_info['device_brand'] = 'Xiaomi'
            device_info['device_name'] = 'Xiaomi'
        elif 'huawei' in user_agent_lower:
            device_info['device_brand'] = 'Huawei'
            device_info['device_name'] = 'Huawei'
        elif 'oneplus' in user_agent_lower:
            device_info['device_brand'] = 'OnePlus'
            device_info['device_name'] = 'OnePlus'
        elif 'google' in user_agent_lower or 'pixel' in user_agent_lower:
            device_info['device_brand'] = 'Google'
            device_info['device_name'] = 'Google Pixel'
        else:
            device_info['device_name'] = 'Android Phone'
        
        if device_info['is_tablet']:
            device_info['device_name'] = 'Android Tablet'
    
    elif 'iphone' in user_agent_lower:
        device_info['os'] = 'iOS'
        device_info['device_type'] = 'Mobile'
        device_info['is_mobile'] = True
        device_info['device_name'] = 'iPhone'
        match = re.search(r'os (\d+_\d+)', user_agent_lower)
        if match:
            device_info['os_version'] = match.group(1).replace('_', '.')
    
    elif 'ipad' in user_agent_lower:
        device_info['os'] = 'iOS'
        device_info['device_type'] = 'Tablet'
        device_info['is_tablet'] = True
        device_info['device_name'] = 'iPad'
        device_info['is_mobile'] = False
        match = re.search(r'os (\d+_\d+)', user_agent_lower)
        if match:
            device_info['os_version'] = match.group(1).replace('_', '.')
    
    elif 'windows' in user_agent_lower:
        device_info['os'] = 'Windows'
        if 'windows nt 10.0' in user_agent_lower:
            device_info['os_version'] = '10/11'
        elif 'windows nt 6.1' in user_agent_lower:
            device_info['os_version'] = '7'
        elif 'windows nt 6.2' in user_agent_lower:
            device_info['os_version'] = '8'
        elif 'windows nt 6.3' in user_agent_lower:
            device_info['os_version'] = '8.1'
        device_info['device_name'] = f'Windows PC'
    
    elif 'mac' in user_agent_lower:
        device_info['os'] = 'macOS'
        device_info['device_name'] = 'Mac'
        if 'intel' in user_agent_lower:
            device_info['device_name'] = 'Mac Intel'
        elif 'apple m' in user_agent_lower:
            device_info['device_name'] = 'Mac Apple Silicon'
    
    elif 'linux' in user_agent_lower:
        device_info['os'] = 'Linux'
        device_info['device_name'] = 'Linux PC'
    
    if device_info['device_name'] == 'Unknown':
        if device_info['is_mobile']:
            device_info['device_name'] = 'Mobile Device'
        elif device_info['is_tablet']:
            device_info['device_name'] = 'Tablet'
        else:
            device_info['device_name'] = 'Desktop Computer'
    
    return device_info

# ========== ADVANCED SESSION MANAGEMENT ==========

def init_advanced_session_table():
    db_path = os.path.join(BASE_DIR, 'hostx.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            session_id TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            device_name TEXT,
            browser TEXT,
            os TEXT,
            login_time TEXT,
            last_activity TEXT,
            is_active INTEGER DEFAULT 1,
            accept_header TEXT,
            accept_language TEXT,
            accept_encoding TEXT,
            connection_header TEXT,
            cache_control TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def extract_all_headers():
    headers = {
        'Accept': request.headers.get('Accept', '*/*'),
        'Accept-Language': request.headers.get('Accept-Language', 'en-US,en;q=0.9'),
        'Accept-Encoding': request.headers.get('Accept-Encoding', 'gzip, deflate'),
        'Connection': request.headers.get('Connection', 'keep-alive'),
        'Cache-Control': request.headers.get('Cache-Control', 'no-cache, no-store'),
        'User-Agent': request.headers.get('User-Agent', 'Unknown'),
        'Referer': request.headers.get('Referer', ''),
        'Origin': request.headers.get('Origin', ''),
        'Host': request.headers.get('Host', ''),
        'X-Forwarded-For': request.headers.get('X-Forwarded-For', ''),
        'X-Real-IP': request.headers.get('X-Real-IP', ''),
        'Authorization': request.headers.get('Authorization', ''),
        'Cookie': request.headers.get('Cookie', '')
    }
    return headers

def save_full_session(username, session_id, ip_address, headers):
    try:
        user_agent = headers.get('User-Agent', '')
        device_info = parse_user_agent_advanced(user_agent)
        
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE user_sessions 
            SET is_active = 0 
            WHERE username = ? AND is_active = 1
        ''', (username,))
        
        cursor.execute('''
            INSERT INTO user_sessions 
            (username, session_id, ip_address, user_agent, device_name, browser, os, 
             login_time, last_activity, is_active, accept_header, accept_language, 
             accept_encoding, connection_header, cache_control)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        ''', (username, session_id, ip_address, user_agent[:500],
              device_info['device_name'], device_info['browser'], device_info['os'],
              datetime.now().isoformat(), datetime.now().isoformat(),
              headers.get('Accept', '*/*'), headers.get('Accept-Language', 'en-US,en;q=0.9'),
              headers.get('Accept-Encoding', 'gzip, deflate'), headers.get('Connection', 'keep-alive'),
              headers.get('Cache-Control', 'no-cache, no-store')))
        
        conn.commit()
        conn.close()
        
        print(f"[SESSION] New session: {username} | {device_info['device_name']} | {ip_address}")
        return True
    except Exception as e:
        print(f"Error saving session: {e}")
        return False

def get_all_sessions_for_admin():
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, session_id, ip_address, device_name, browser, os, 
                   login_time, last_activity, is_active, accept_header, accept_language,
                   accept_encoding, connection_header, cache_control, user_agent
            FROM user_sessions 
            ORDER BY login_time DESC
        ''')
        sessions = cursor.fetchall()
        conn.close()
        
        sessions_list = []
        for s in sessions:
            login_time = datetime.fromisoformat(s[6]) if s[6] else datetime.now()
            duration = datetime.now() - login_time
            
            device_info = parse_user_agent_advanced(s[14] or '')
            
            sessions_list.append({
                'username': s[0],
                'session_id': s[1],
                'ip_address': s[2] or 'Unknown',
                'device_name': device_info['device_name'] if device_info['device_name'] != 'Unknown' else (s[3] or 'Unknown'),
                'browser': device_info['browser'] if device_info['browser'] != 'Unknown' else (s[4] or 'Unknown'),
                'os': device_info['os'] if device_info['os'] != 'Unknown' else (s[5] or 'Unknown'),
                'device_type': device_info['device_type'],
                'is_mobile': device_info['is_mobile'],
                'login_time': s[6],
                'last_activity': s[7],
                'is_active': bool(s[8]),
                'duration': f"{duration.days}d {duration.seconds//3600}h" if duration.days > 0 else f"{duration.seconds//3600}h",
                'headers': {
                    'Accept': s[9] or '*/*',
                    'Accept-Language': s[10] or 'en-US,en;q=0.9',
                    'Accept-Encoding': s[11] or 'gzip, deflate',
                    'Connection': s[12] or 'keep-alive',
                    'Cache-Control': s[13] or 'no-cache, no-store',
                    'User-Agent': s[14] or 'Unknown'
                }
            })
        return sessions_list
    except Exception as e:
        print(f"Error getting sessions: {e}")
        return []

def get_session_headers_by_id(session_id):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT accept_header, accept_language, accept_encoding, connection_header, 
                   cache_control, user_agent, ip_address, device_name, os, browser
            FROM user_sessions 
            WHERE session_id = ?
        ''', (session_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            device_info = parse_user_agent_advanced(result[5] or '')
            
            return {
                'Accept': result[0] or '*/*',
                'Accept-Language': result[1] or 'en-US,en;q=0.9',
                'Accept-Encoding': result[2] or 'gzip, deflate',
                'Connection': result[3] or 'keep-alive',
                'Cache-Control': result[4] or 'no-cache, no-store',
                'User-Agent': result[5] or 'Unknown',
                'IP': result[6] or 'Unknown',
                'Device': device_info['device_name'],
                'Device_Type': device_info['device_type'],
                'Device_Brand': device_info['device_brand'],
                'OS': device_info['os'],
                'OS_Version': device_info['os_version'],
                'Browser': device_info['browser'],
                'Browser_Version': device_info['browser_version'],
                'Is_Mobile': device_info['is_mobile'],
                'Is_Tablet': device_info['is_tablet']
            }
        return None
    except Exception as e:
        print(f"Error getting session headers: {e}")
        return None

def terminate_session_by_admin(username, session_id):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions 
            SET is_active = 0 
            WHERE username = ? AND session_id = ?
        ''', (username, session_id))
        conn.commit()
        conn.close()
        
        log_security_event('session_terminated_by_admin', request.remote_addr, username, 
                         f'Session {session_id[:8]}... terminated by admin', 'high')
        return True
    except:
        return False

def is_session_valid_advanced(username, session_id):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT is_active FROM user_sessions 
            WHERE username = ? AND session_id = ?
        ''', (username, session_id))
        result = cursor.fetchone()
        conn.close()
        
        return result and result[0] == 1
    except:
        return True

init_advanced_session_table()

# ========== DATA FILES ==========
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
SERVERS_FILE = os.path.join(BASE_DIR, 'servers.json')
PACKAGES_FILE = os.path.join(BASE_DIR, 'packages.json')
CUSTOM_ORDERS_FILE = os.path.join(BASE_DIR, 'custom_orders.json')

def load_users():
    data = safe_load_json(USERS_FILE)
    return data if isinstance(data, dict) else {}

def save_users(users):
    if isinstance(users, dict):
        return save_json_safe(USERS_FILE, users)
    return False

def load_servers():
    data = safe_load_json(SERVERS_FILE)
    return data if isinstance(data, dict) else {}

def save_servers(servers):
    if isinstance(servers, dict):
        return save_json_safe(SERVERS_FILE, servers)
    return False

def load_packages():
    data = safe_load_json(PACKAGES_FILE)
    return data if isinstance(data, dict) else {}

def save_packages(packages):
    if isinstance(packages, dict):
        return save_json_safe(PACKAGES_FILE, packages)
    return False

def load_custom_orders():
    data = safe_load_json(CUSTOM_ORDERS_FILE)
    return data if isinstance(data, list) else []

def save_custom_orders(orders):
    if isinstance(orders, list):
        return save_json_safe(CUSTOM_ORDERS_FILE, orders)
    return False

# ========== DATABASE FUNCTIONS ==========
def init_db():
    db_path = os.path.join(BASE_DIR, 'hostx.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            last_login TEXT,
            login_count INTEGER DEFAULT 0,
            created_at TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'active'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT,
            message TEXT,
            ip_address TEXT,
            username TEXT,
            created_at TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            ip_address TEXT,
            username TEXT,
            details TEXT,
            severity TEXT,
            created_at TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            server_id TEXT,
            ip_address TEXT,
            created_at TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def log_user_activity(username, action, server_id=None, ip_address=None):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_activity (username, action, server_id, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, action, server_id, ip_address or request.remote_addr, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

def log_security_event(event_type, ip_address, username, details, severity='info'):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_events (event_type, ip_address, username, details, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event_type, ip_address, username, details, severity, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

def update_user_ip(username, ip, user_agent=None):
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users_log WHERE username = ?', (username,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute('''
                UPDATE users_log 
                SET ip_address = ?, last_login = ?, login_count = login_count + 1, user_agent = ?
                WHERE username = ?
            ''', (ip, datetime.now().isoformat(), user_agent, username))
        else:
            cursor.execute('''
                INSERT INTO users_log (username, ip_address, last_login, login_count, created_at, user_agent, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
            ''', (username, ip, datetime.now().isoformat(), 1, datetime.now().isoformat(), user_agent))
        
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_all_users_data():
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users_log ORDER BY last_login DESC')
        users = cursor.fetchall()
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'username': user[1],
                'ip_address': user[2],
                'last_login': user[3],
                'login_count': user[4],
                'created_at': user[5],
                'user_agent': user[6][:50] + '...' if user[6] and len(user[6]) > 50 else user[6],
                'status': user[7] if len(user) > 7 else 'active'
            })
        return user_list
    except:
        return []

def get_security_events():
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 100')
        events = cursor.fetchall()
        conn.close()
        
        event_list = []
        for event in events:
            event_list.append({
                'id': event[0],
                'event_type': event[1],
                'ip_address': event[2],
                'username': event[3] if event[3] else 'Unknown',
                'details': event[4],
                'severity': event[5],
                'created_at': event[6]
            })
        return event_list
    except:
        return []

def get_user_activity():
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user_activity ORDER BY created_at DESC LIMIT 100')
        activities = cursor.fetchall()
        conn.close()
        
        activity_list = []
        for act in activities:
            activity_list.append({
                'id': act[0],
                'username': act[1],
                'action': act[2],
                'server_id': act[3],
                'ip_address': act[4],
                'created_at': act[5]
            })
        return activity_list
    except:
        return []

def get_suspicious_ips():
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, COUNT(*) as count, 
                   GROUP_CONCAT(DISTINCT event_type) as events,
                   MAX(created_at) as last_seen
            FROM security_events 
            GROUP BY ip_address 
            ORDER BY count DESC
            LIMIT 50
        ''')
        suspicious = cursor.fetchall()
        conn.close()
        
        ip_list = []
        for ip in suspicious:
            ip_list.append({
                'ip': ip[0],
                'count': ip[1],
                'events': ip[2],
                'last_seen': ip[3]
            })
        return ip_list
    except:
        return []

init_db()

# ========== DATE PARSING FUNCTIONS ==========
def parse_expiry_date(expiry_str):
    if not expiry_str or expiry_str == "Unlimited":
        return None
    expiry_str = str(expiry_str).strip()
    formats = ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y', '%m-%d-%Y', '%Y/%m/%d', '%d.%m.%Y']
    for fmt in formats:
        try:
            return datetime.strptime(expiry_str, fmt)
        except:
            continue
    try:
        numbers = re.findall(r'\d+', expiry_str)
        if len(numbers) >= 3:
            day, month, year = int(numbers[0]), int(numbers[1]), int(numbers[2])
            if year < 100:
                year += 2000
            return datetime(year, month, day)
    except:
        pass
    return None

def calculate_remaining_time(expiry_date):
    if not expiry_date or expiry_date == "Unlimited":
        return "Unlimited"
    try:
        expiry = parse_expiry_date(expiry_date)
        if not expiry:
            return "Unlimited"
        remaining = expiry - datetime.now()
        if remaining.days < 0:
            return "Expired"
        elif remaining.days == 0:
            hours = remaining.seconds // 3600
            return f"{hours}h left" if hours > 0 else "Today"
        elif remaining.days < 7:
            return f"{remaining.days}d left"
        elif remaining.days < 30:
            weeks = remaining.days // 7
            days = remaining.days % 7
            return f"{weeks}w {days}d left"
        elif remaining.days < 365:
            months = remaining.days // 30
            days = remaining.days % 30
            return f"{months}m {days}d left"
        else:
            years = remaining.days // 365
            months = (remaining.days % 365) // 30
            return f"{years}y {months}m left"
    except:
        return "Unlimited"

def is_account_expired(user_data):
    expiry = user_data.get('expiry', 'Unlimited')
    if not expiry or expiry == "Unlimited":
        return False
    try:
        expiry_date = parse_expiry_date(expiry)
        if not expiry_date:
            return False
        return datetime.now() > expiry_date
    except:
        return False

# ========== HELPER FUNCTIONS ==========
def get_server_folder(server_id):
    folder = os.path.join(BASE_DIR, 'servers', server_id)
    os.makedirs(folder, exist_ok=True)
    return folder

def update_server_log(server_id, message):
    servers = load_servers()
    if server_id in servers:
        if 'logs' not in servers[server_id]:
            servers[server_id]['logs'] = []
        servers[server_id]['logs'].append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        if len(servers[server_id]['logs']) > 200:
            servers[server_id]['logs'] = servers[server_id]['logs'][-200:]
        save_servers(servers)
    print(f"[LOG][{server_id}] {message}")

def get_folder_size(folder):
    total = 0
    if os.path.exists(folder):
        try:
            result = os.popen(f"du -sb {folder} 2>/dev/null | cut -f1").read()
            if result and result.strip().isdigit():
                return round(int(result.strip()) / (1024 * 1024), 2)
        except:
            pass
        for dirpath, dirnames, filenames in os.walk(folder):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    try:
                        total += os.path.getsize(fp)
                    except:
                        pass
    return round(total / (1024 * 1024), 2)

def calculate_speed(cpu_type):
    speeds = {
        "AMD Ryzen 9 9950X": 5.8, "AMD Ryzen 9 9900X": 5.6,
        "AMD Ryzen 9 7950X": 5.7, "AMD Ryzen 9 7900X": 5.6,
        "AMD Ryzen 7 7800X3D": 5.0, "AMD Ryzen 5 7600X": 5.3,
        "Intel Core Ultra 9 285K": 5.7, "Intel Core i9-14900K": 6.0,
        "Intel Core i9-13900K": 5.8, "Intel Core i7-13700K": 5.4,
        "AMD Ryzen 9 5950X": 4.9, "AMD Ryzen 7 5800X3D": 4.5,
        "Intel Core i9-12900K": 5.2, "Apple M2 Ultra": 3.7,
        "Snapdragon 8 Gen 3": 3.3, "Ryzen 7 3700X": 4.2,
        "Ryzen 5 3500X": 3.8, "Intel Core i3": 2.5,
        "Snapdragon": 2.5, "Admin - Snapdragon": 4.5
    }
    return speeds.get(cpu_type, 2.5)

# ========== REAL SYSTEM STATS FUNCTIONS ==========
def get_real_cpu_usage():
    try:
        result = os.popen("top -bn1 2>/dev/null | head -3").read()
        import re
        cpu_match = re.search(r'(\d+\.?\d*)%?\s*(?:cpu|Cpu)', result.lower())
        if cpu_match:
            cpu_val = float(cpu_match.group(1))
            if cpu_val > 100:
                cpu_val = cpu_val / 8
            return round(min(cpu_val, 100), 1)
        result2 = os.popen("ps -eo pcpu | awk '{sum+=$1} END {print sum}' 2>/dev/null").read()
        if result2 and result2.strip():
            cpu_sum = float(result2.strip())
            return round(min(cpu_sum, 100), 1)
        uptime_res = os.popen("uptime 2>/dev/null").read()
        if 'load average' in uptime_res:
            load = uptime_res.split('load average:')[-1].split(',')[0].strip()
            load_val = float(load)
            cpu_count = os.cpu_count() or 4
            cpu_pct = (load_val / cpu_count) * 100
            return round(min(cpu_pct, 100), 1)
        return random.randint(1, 15)
    except:
        return random.randint(1, 15)

def get_real_ram_usage():
    try:
        result = os.popen("free -m 2>/dev/null").read().splitlines()
        if len(result) > 1:
            mem_parts = result[1].split()
            if len(mem_parts) >= 3:
                used = int(mem_parts[2])
                total = int(mem_parts[1])
                if used > total:
                    used = total - 100
                return max(used, 50)
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            total_kb = 0
            for line in meminfo.split('\n'):
                if 'MemTotal:' in line:
                    total_kb = int(line.split()[1])
                    break
            if total_kb > 0:
                used_mb = total_kb // 1024 // 2
                return max(used_mb, 50)
        return 500
    except:
        return 500

def get_real_disk_usage(server_id):
    folder = get_server_folder(server_id)
    total = 0
    if os.path.exists(folder):
        try:
            result = os.popen(f"du -sb {folder} 2>/dev/null | cut -f1").read()
            if result and result.strip().isdigit():
                return round(int(result.strip()) / (1024 * 1024), 2)
        except:
            pass
        for dirpath, dirnames, filenames in os.walk(folder):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    try:
                        total += os.path.getsize(fp)
                    except:
                        pass
    return round(total / (1024 * 1024), 2)

def get_real_process_load():
    try:
        result = os.popen("uptime 2>/dev/null").read()
        if 'load average' in result:
            load_avg = result.split('load average:')[-1].split(',')[0].strip()
            load_val = float(load_avg)
            cpu_count = os.cpu_count() or 4
            load_percent = (load_val / cpu_count) * 100
            return round(min(load_percent, 100), 1)
        return random.randint(1, 10)
    except:
        return random.randint(1, 10)

def get_network_stats():
    try:
        if os.path.exists('/proc/net/dev'):
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
            total_recv = 0
            total_sent = 0
            for line in lines[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].strip(':')
                    if iface not in ['lo', 'docker0', 'veth']:
                        try:
                            total_recv += int(parts[1])
                            total_sent += int(parts[9])
                        except:
                            pass
            return {
                'in': round(total_recv / (1024 * 1024), 2),
                'out': round(total_sent / (1024 * 1024), 2)
            }
    except:
        pass
    return {'in': 0, 'out': 0}

# ========== DEFAULT USERS ==========
if not os.path.exists(USERS_FILE):
    default_users = {
        "admin": {
            "password": "admin123",
            "role": "admin",
            "ram": "33 GB",
            "storage": "258 GB",
            "cpu": "Admin - Snapdragon",
            "cores": 8,
            "expiry": "2027-01-08",
            "created_at": datetime.now().isoformat()
        }
    }
    save_users(default_users)
    print("✅ Default admin user created: admin / admin123")

if not os.path.exists(PACKAGES_FILE):
    default_packages = {
        "package_1": {"id": "package_1", "name": "Ryzen Pro", "ram": "16 GB",
            "storage": "285 GB", "cpu": "Ryzen 7 3700X", "cores": 2,
            "price": "$29.99", "whatsapp": "541700591"},
        "package_2": {"id": "package_2", "name": "Ryzen Standard", "ram": "8 GB",
            "storage": "128 GB", "cpu": "Ryzen 5 3500X", "cores": 3,
            "price": "$19.99", "whatsapp": "541700591"},
        "package_3": {"id": "package_3", "name": "Basic Server", "ram": "4 GB",
            "storage": "64 GB", "cpu": "Intel Core i3", "cores": 2,
            "price": "$9.99", "whatsapp": "541700591"}
    }
    save_packages(default_packages)

if not os.path.exists(CUSTOM_ORDERS_FILE):
    save_custom_orders([])

running_processes = {}

# ========== MAIN SECURITY CHECK ==========
@app.before_request
def security_check():
    if request.endpoint in ['banned_page', 'static', 'admin_blocked_countries', 'admin_security', 'login', 'logout', 'refresh_captcha', 'admin_sessions', 'copy_session_headers', 'terminate_session_admin']:
        return None
    
    ip = get_client_ip()
    
    if is_ip_banned(ip):
        return render_template('banned.html', ban_duration=BAN_DURATION_HOURS, ip=ip, reason="Banned"), 403
    
    if not rate_limit_check(ip):
        return render_template('banned.html', ban_duration=BAN_DURATION_HOURS, ip=ip, reason="Rate limit"), 403
    
    detect_ddos_behavior(ip, request.endpoint)
    
    if 'user' in session and 'session_id' in session:
        if not is_session_valid_advanced(session['user'], session['session_id']):
            session.clear()
            return "❌ Your session has been revoked by admin or logged in from another device!", 401
    
    if 'user' in session and not validate_session_fingerprint():
        session.clear()
        return "Session hijacking detected!", 403
    
    allowed, msg = country_block_check(ip)
    if not allowed:
        return msg, 403
    
    return None

@app.route('/banned')
def banned_page():
    ip = get_client_ip()
    return render_template('banned.html', ban_duration=BAN_DURATION_HOURS, ip=ip, reason="You have been banned")

# ========== ADMIN SESSION MANAGEMENT ROUTES ==========

@app.route('/admin/sessions')
def admin_sessions():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    all_sessions = get_all_sessions_for_admin()
    
    stats = {
        'total': len(all_sessions),
        'active': len([s for s in all_sessions if s['is_active']]),
        'inactive': len([s for s in all_sessions if not s['is_active']]),
        'unique_users': len(set([s['username'] for s in all_sessions]))
    }
    
    return render_template('admin_sessions.html',
                         sessions=all_sessions,
                         stats=stats,
                         csrf_token=generate_csrf_token())

@app.route('/admin/copy_session_headers/<session_id>')
def copy_session_headers(session_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({"error": "unauthorized"}), 401
    
    headers = get_session_headers_by_id(session_id)
    if headers:
        return jsonify(headers)
    
    return jsonify({"error": "Session not found"}), 404

@app.route('/admin/terminate_session/<session_id>')
def terminate_session_admin(session_id):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT username FROM user_sessions WHERE session_id = ?', (session_id,))
        result = cursor.fetchone()
        
        if result:
            username = result[0]
            cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE session_id = ?', (session_id,))
            conn.commit()
            log_security_event('session_terminated', get_client_ip(), username, 
                             f'Session {session_id[:8]}... terminated by admin', 'high')
        
        conn.close()
    except:
        pass
    
    return redirect(url_for('admin_sessions'))

@app.route('/admin/terminate_user_sessions/<username>')
def terminate_user_sessions(username):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        
        log_security_event('all_sessions_terminated', get_client_ip(), username, 
                         f'All sessions for {username} terminated by admin', 'critical')
    except:
        pass
    
    return redirect(url_for('admin_sessions'))

# ========== API ENDPOINTS ==========
@app.route('/api/get_file_content/<server_id>/<filename>')
def get_file_content(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"success": True, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_file/<server_id>/<filename>', methods=['POST'])
def save_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    data = request.get_json()
    content = data.get('content', '')
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        update_server_log(server_id, f"File edited: {filename}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rename_file/<server_id>/<filename>', methods=['POST'])
def rename_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    folder = get_server_folder(server_id)
    old_path = os.path.join(folder, filename)
    if not os.path.exists(old_path) or not os.path.isfile(old_path):
        return jsonify({"error": "File not found"}), 404
    data = request.get_json()
    new_name = data.get('new_name', '')
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    new_path = os.path.join(folder, new_name)
    try:
        os.rename(old_path, new_path)
        update_server_log(server_id, f"File renamed: {filename} → {new_name}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/server_details/<server_id>')
def api_server_details(server_id):
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    server = servers[server_id]
    
    cpu_usage = get_real_cpu_usage()
    ram_usage = get_real_ram_usage()
    disk_usage = get_real_disk_usage(server_id)
    process_load = get_real_process_load()
    network_stats = get_network_stats()
    
    ram_from_server = server.get('ram', '4 GB')
    try:
        ram_total_display = int(ram_from_server.split()[0])
    except:
        ram_total_display = 4
    
    disk_total = server.get('storage', '50 GB')
    try:
        disk_total_num = int(disk_total.split()[0])
    except:
        disk_total_num = 50
    
    return jsonify({
        "status": server.get('status', 'stopped'),
        "ram_used": ram_usage,
        "ram_total": ram_total_display,
        "cpu_usage": cpu_usage,
        "process_load": process_load,
        "disk_used": disk_usage,
        "disk_total": disk_total,
        "disk_total_num": disk_total_num,
        "network_in": network_stats['in'],
        "network_out": network_stats['out'],
        "logs": server.get('logs', [])[-50:]
    })

@app.route('/api/system_info')
def system_info():
    hostname = socket.gethostname()
    os_platform = f"{platform.system()} {platform.release()}"
    python_version = f"{platform.python_version()}"
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = get_client_ip()
    return jsonify({
        "hostname": hostname, "os_platform": os_platform,
        "python_version": python_version, "server_time": server_time,
        "client_ip": client_ip, "uptime": "N/A"
    })

@app.route('/api/get_server_logs/<server_id>')
def get_server_logs(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    logs = servers[server_id].get('logs', [])
    last_logs = logs[-50:] if len(logs) > 50 else logs
    return jsonify({"success": True, "logs": last_logs, "count": len(last_logs), "total": len(logs)})

@app.route('/api/upload_file/<server_id>', methods=['POST'])
def upload_file(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    folder = get_server_folder(server_id)
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    filename = file.filename
    
    if filename.endswith('.exe') or filename.endswith('.sh') or filename.endswith('.bat'):
        return jsonify({"error": "Executable files not allowed"}), 400
    
    filepath = os.path.join(folder, filename)
    counter = 1
    while os.path.exists(filepath):
        name, ext = os.path.splitext(filename)
        filepath = os.path.join(folder, f"{name}_{counter}{ext}")
        counter += 1
    
    file.save(filepath)
    update_server_log(server_id, f"Uploaded: {filename}")
    
    if filename.endswith('.zip'):
        update_server_log(server_id, "📦 Extracting ZIP file...")
        try:
            temp_dir = os.path.join(folder, f"_temp_zip_{int(time.time())}")
            os.makedirs(temp_dir, exist_ok=True)
            
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            for item in os.listdir(temp_dir):
                src = os.path.join(temp_dir, item)
                dst = os.path.join(folder, item)
                if os.path.exists(dst):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    else:
                        os.remove(dst)
                shutil.move(src, dst)
            
            shutil.rmtree(temp_dir)
            os.remove(filepath)
            update_server_log(server_id, "✅ ZIP extracted successfully!")
            
            for f in os.listdir(folder):
                if f.lower() in ['main.py', 'app.py', 'application.py', 'server.py']:
                    update_server_log(server_id, f"📁 Found main file: {f}")
                    break
            
            req_file = os.path.join(folder, 'requirements.txt')
            if os.path.exists(req_file):
                update_server_log(server_id, "📦 Installing requirements...")
                subprocess.run(['pip3', 'install', '-r', req_file], capture_output=True, timeout=180, cwd=folder)
                update_server_log(server_id, "✅ Requirements installed")
                
        except zipfile.BadZipFile:
            update_server_log(server_id, "❌ Error: Invalid ZIP file")
        except Exception as e:
            update_server_log(server_id, f"❌ ZIP error: {str(e)}")
    
    elif filename == 'requirements.txt':
        update_server_log(server_id, "📦 Installing packages...")
        subprocess.run(['pip3', 'install', '-r', filepath], capture_output=True, timeout=180, cwd=folder)
        update_server_log(server_id, "✅ Packages installed")
    
    elif filename.endswith('.py'):
        if filename.lower() in ['app.py', 'main.py', 'application.py']:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    if 'flask' in f.read().lower():
                        update_server_log(server_id, "🔧 Flask detected, installing...")
                        subprocess.run(['pip3', 'install', 'flask'], capture_output=True, cwd=folder)
            except:
                pass
    
    folder_size = get_real_disk_usage(server_id)
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['current_storage_used'] = folder_size
        save_servers(servers)
    
    return jsonify({"success": True, "message": f"Uploaded: {filename}", "storage_used": folder_size})

@app.route('/api/start_server/<server_id>', methods=['POST'])
def start_server(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    
    users = load_users()
    user_data = users.get(session['user'], {})
    if is_account_expired(user_data):
        return jsonify({"error": "Your account has expired"}), 403
    
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    
    if server_id in running_processes:
        process = running_processes[server_id]
        if process and process.poll() is None:
            return jsonify({"success": False, "message": "Server is already running"}), 200
    
    folder = get_server_folder(server_id)
    
    main_file = None
    for f in os.listdir(folder):
        if f.endswith('.py') and not f.endswith('.bak'):
            if f.lower() in ['app.py', 'main.py', 'application.py', 'server.py']:
                main_file = f
                break
    
    if not main_file:
        for f in os.listdir(folder):
            if f.endswith('.py') and not f.endswith('.bak'):
                main_file = f
                break
    
    if not main_file:
        update_server_log(server_id, "❌ No Python file found")
        return jsonify({"error": "No Python file found"}), 400
    
    main_file_path = os.path.join(folder, main_file)
    update_server_log(server_id, f"📁 Found: {main_file}")
    
    req_file = os.path.join(folder, 'requirements.txt')
    if os.path.exists(req_file):
        update_server_log(server_id, "📦 Installing requirements...")
        result = subprocess.run(['pip3', 'install', '-r', req_file], capture_output=True, text=True, timeout=120, cwd=folder)
        if result.returncode == 0:
            update_server_log(server_id, "✅ Requirements installed")
        else:
            update_server_log(server_id, f"⚠️ Install error: {result.stderr[:200]}")
    
    try:
        update_server_log(server_id, f"🚀 Starting: python3 {main_file}")
        
        process = subprocess.Popen(
            ['python3', main_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=folder
        )
        
        time.sleep(3)
        
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            error_msg = stderr if stderr else stdout
            
            if error_msg:
                update_server_log(server_id, "❌ Error details:")
                error_lines = error_msg.strip().split('\n')[:10]
                for line in error_lines:
                    if line.strip():
                        update_server_log(server_id, f"   {line.strip()}")
            else:
                update_server_log(server_id, "❌ Server failed to start (unknown error)")
            
            return jsonify({"error": "Server failed to start. Check logs for details"}), 500
        
        running_processes[server_id] = process
        servers[server_id]['status'] = 'running'
        servers[server_id]['pid'] = process.pid
        save_servers(servers)
        
        update_server_log(server_id, f"✅ Server started successfully (PID: {process.pid})")
        
        def read_logs():
            while True:
                if server_id not in running_processes:
                    break
                proc = running_processes.get(server_id)
                if not proc or proc.poll() is not None:
                    break
                try:
                    line = proc.stdout.readline()
                    if line:
                        update_server_log(server_id, line.strip())
                except:
                    break
                time.sleep(0.1)
            
            servers_reload = load_servers()
            if server_id in servers_reload:
                servers_reload[server_id]['status'] = 'stopped'
                save_servers(servers_reload)
                update_server_log(server_id, "🛑 Server stopped")
            if server_id in running_processes:
                del running_processes[server_id]
        
        threading.Thread(target=read_logs, daemon=True).start()
        return jsonify({"success": True, "message": f"Started {main_file}"})
        
    except Exception as e:
        update_server_log(server_id, f"❌ Exception: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_server/<server_id>', methods=['POST'])
def stop_server(server_id):
    if server_id in running_processes:
        process = running_processes[server_id]
        if process and process.poll() is None:
            update_server_log(server_id, "🛑 Stopping...")
            process.terminate()
            time.sleep(2)
            if process.poll() is None:
                process.kill()
            update_server_log(server_id, "✅ Stopped")
        del running_processes[server_id]
    
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['status'] = 'stopped'
        save_servers(servers)
    
    return jsonify({"success": True})

@app.route('/api/restart_server/<server_id>', methods=['POST'])
def restart_server(server_id):
    stop_server(server_id)
    time.sleep(2)
    return start_server(server_id)

@app.route('/api/clear_logs/<server_id>', methods=['POST'])
def clear_logs(server_id):
    servers = load_servers()
    if server_id in servers:
        servers[server_id]['logs'] = []
        save_servers(servers)
        update_server_log(server_id, "🗑 Logs cleared")
    return jsonify({"success": True})

@app.route('/api/delete_file/<server_id>/<filename>', methods=['DELETE'])
def delete_file(server_id, filename):
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        os.remove(filepath)
        update_server_log(server_id, f"Deleted: {filename}")
        return jsonify({"success": True})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/list_files/<server_id>')
def list_files(server_id):
    folder = get_server_folder(server_id)
    files = []
    if os.path.exists(folder):
        for f in os.listdir(folder):
            filepath = os.path.join(folder, f)
            if os.path.isfile(filepath) and not f.endswith('.bak'):
                files.append({"name": f, "size": os.path.getsize(filepath), "is_python": f.endswith('.py')})
    return jsonify({"files": files})

@app.route('/api/delete_server/<server_id>', methods=['DELETE'])
def delete_server(server_id):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    servers = load_servers()
    if server_id not in servers:
        return jsonify({"error": "not found"}), 404
    if servers[server_id]['owner'] != session['user'] and session.get('role') != 'admin':
        return jsonify({"error": "unauthorized"}), 403
    if server_id in running_processes:
        process = running_processes[server_id]
        if process and process.poll() is None:
            process.terminate()
            time.sleep(1)
            if process.poll() is None:
                process.kill()
        del running_processes[server_id]
    folder = get_server_folder(server_id)
    if os.path.exists(folder):
        shutil.rmtree(folder)
    del servers[server_id]
    save_servers(servers)
    return jsonify({"success": True})

@app.route('/api/update_credentials', methods=['POST'])
def update_credentials():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('current_password')
    new_username = data.get('new_username')
    new_password = data.get('new_password')
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    if users[username]['password'] != current_password:
        return jsonify({"error": "Current password is incorrect"}), 401
    if new_username and new_username != username:
        if new_username in users:
            return jsonify({"error": "Username already exists"}), 400
        users[new_username] = users.pop(username)
        session['user'] = new_username
        username = new_username
    if new_password:
        users[username]['password'] = new_password
    save_users(users)
    return jsonify({"success": True})

@app.route('/api/admin_monitor')
def admin_monitor():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    users = load_users()
    servers = load_servers()
    user_list = []
    for u, data in users.items():
        user_servers = [s for s in servers.values() if s.get('owner') == u]
        user_list.append({"username": u, "role": data.get('role', 'user'), "servers": len(user_servers)})
    server_list = []
    for sid, s in servers.items():
        server_list.append({"id": sid, "name": s.get('name', 'Unknown'), "owner": s.get('owner', 'Unknown'), "status": s.get('status', 'stopped')})
    return jsonify({"users": user_list, "servers": server_list})

# ========== ADMIN SECURITY ROUTES ==========
@app.route('/admin/security')
def admin_security():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    users_data = get_all_users_data()
    security_events = get_security_events()
    user_activity = get_user_activity()
    suspicious_ips = get_suspicious_ips()
    banned_ips = load_banned_ips()
    
    return render_template('admin_security.html',
                         users_data=users_data,
                         security_events=security_events,
                         user_activity=user_activity,
                         suspicious_ips=suspicious_ips,
                         banned_ips=banned_ips,
                         csrf_token=generate_csrf_token())

@app.route('/admin/ban_ip_from_security/<ip>')
def admin_ban_ip_from_security(ip):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    ban_ip(ip, "Banned from security panel")
    log_security_event('manual_ban', ip, session['user'], f'IP {ip} banned by admin', 'high')
    
    return redirect(url_for('admin_security'))

@app.route('/admin/clear_security_events')
def admin_clear_security_events():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM security_events')
        conn.commit()
        conn.close()
    except:
        pass
    
    return redirect(url_for('admin_security'))

@app.route('/api/get_user_details/<username>')
def api_get_user_details(username):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({"error": "unauthorized"}), 401
    
    try:
        db_path = os.path.join(BASE_DIR, 'hostx.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users_log WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                'username': user[1],
                'ip_address': user[2],
                'last_login': user[3],
                'login_count': user[4],
                'created_at': user[5],
                'user_agent': user[6],
                'status': user[7] if len(user) > 7 else 'active'
            })
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========== ROUTES ==========
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '')
        ip = get_client_ip()
        
        if captcha != session.get('captcha'):
            return redirect(url_for('login', error='captcha'))
        
        allowed, msg = check_brute_force(ip, username)
        if not allowed:
            return redirect(url_for('login', error='captcha'))
        
        users = load_users()
        
        if username not in users:
            record_failed_attempt(ip, username)
            return redirect(url_for('login', error='user'))
        
        if users[username]['password'] != password:
            record_failed_attempt(ip, username)
            return redirect(url_for('login', error='password'))
        
        if is_account_expired(users[username]):
            return redirect(url_for('login', error='expired'))
        
        session_id = secrets.token_hex(32)
        
        headers = extract_all_headers()
        
        save_full_session(username, session_id, ip, headers)
        
        session['user'] = username
        session['role'] = users[username]['role']
        session['session_id'] = session_id
        regenerate_session()
        
        update_user_ip(username, ip, request.headers.get('User-Agent'))
        log_user_activity(username, 'login', None, ip)
        log_security_event('successful_login', ip, username, f'User {username} logged in from {ip}', 'info')
        
        return redirect(url_for('dashboard'))
    
    session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    error = request.args.get('error', '')
    return render_template('login.html', captcha=session['captcha'], csrf_token=generate_csrf_token(), error=error)

@app.route('/api/download_file/<server_id>/<filename>')
def download_file(server_id, filename):
    if 'user' not in session:
        return jsonify({"error": "unauthorized"}), 401
    folder = get_server_folder(server_id)
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return "File not found", 404
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    users = load_users()
    user_data = users.get(session['user'], {})
    
    if is_account_expired(user_data):
        session.clear()
        return redirect(url_for('login', error='expired'))
    
    servers = load_servers()
    packages = load_packages()
    user_servers = {}
    for sid, s in servers.items():
        if s.get('owner') == session['user']:
            server_data = s.copy()
            server_data['cpu_speed'] = calculate_speed(server_data.get('cpu_type', 'Snapdragon'))
            server_data['storage_used'] = f"{get_real_disk_usage(sid)} MB"
            server_data['storage_percent'] = min((get_real_disk_usage(sid) / int(server_data.get('storage', '50 GB').split()[0])) * 100, 100)
            user_servers[sid] = server_data
    
    total_storage_used = 0.0
    for sid in user_servers:
        total_storage_used += get_real_disk_usage(sid)
    
    cpu_type = user_data.get('cpu', 'Snapdragon')
    cpu_speed = calculate_speed(cpu_type)
    remaining_time = calculate_remaining_time(user_data.get('expiry', 'Unlimited'))
    ram_allocated = user_data.get('ram', '4 GB')
    storage_display = f"{total_storage_used:.2f} MB" if total_storage_used > 0 else "0 MB"
    
    return render_template('dashboard.html',
                         user=session['user'], role=session.get('role', 'user'),
                         ram=ram_allocated, storage=user_data.get('storage', 'N/A'),
                         cpu=cpu_type, cpu_speed=cpu_speed, remaining_time=remaining_time,
                         servers_count=len(user_servers), storage_used=storage_display,
                         user_servers=user_servers, packages=packages,
                         csrf_token=generate_csrf_token())

@app.route('/buy')
def buy():
    if 'user' not in session:
        return redirect(url_for('login'))
    users = load_users()
    user_data = users.get(session['user'], {})
    if is_account_expired(user_data):
        return redirect(url_for('login', error='expired'))
    packages = load_packages()
    return render_template('buy.html', packages=packages, csrf_token=generate_csrf_token())

@app.route('/purchase/<package_id>')
def purchase(package_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    users = load_users()
    user_data = users.get(session['user'], {})
    if is_account_expired(user_data):
        return redirect(url_for('login', error='expired'))
    packages = load_packages()
    if package_id not in packages:
        return "Package not found", 404
    package = packages[package_id]
    message = f"Hello! I want to purchase {package['name']} server%0ARAM: {package['ram']}%0AStorage: {package['storage']}%0ACPU: {package['cpu']}%0APrice: {package['price']}%0AMy username: {session['user']}"
    whatsapp_url = f"https://wa.me/541700591?text={message}"
    return redirect(whatsapp_url)

@app.route('/admin_create_server', methods=['POST'])
def admin_create_server():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    username = request.form.get('username', '')
    server_name = request.form.get('server_name', '')
    cpu = request.form.get('cpu', '')
    ram = request.form.get('ram', '')
    storage = request.form.get('storage', '')
    cores = request.form.get('cores', '2')
    users = load_users()
    if username not in users:
        return "User not found", 404
    if is_account_expired(users[username]):
        return "Cannot create server for expired account", 403
    servers = load_servers()
    server_id = str(uuid.uuid4())[:8]
    servers[server_id] = {"owner": username, "name": server_name, "status": "stopped",
        "pid": None, "logs": [f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Server created by admin"],
        "cpu_type": cpu, "ram": ram, "storage": storage, "cores": cores,
        "current_storage_used": 0, "created_at": datetime.now().isoformat()}
    save_servers(servers)
    get_server_folder(server_id)
    return redirect(url_for('terminal', server_id=server_id))

@app.route('/create_server', methods=['POST'])
def create_server():
    if 'user' not in session:
        return redirect(url_for('login'))
    users = load_users()
    user_data = users.get(session['user'], {})
    if is_account_expired(user_data):
        return redirect(url_for('login', error='expired'))
    server_name = request.form.get('server_name', '')
    username = session['user']
    servers = load_servers()
    server_id = str(uuid.uuid4())[:8]
    servers[server_id] = {"owner": username, "name": server_name, "status": "stopped",
        "pid": None, "logs": [f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Server created"],
        "cpu_type": user_data.get('cpu', 'Snapdragon'),
        "ram": user_data.get('ram', '4 GB'),
        "storage": user_data.get('storage', '50 GB'),
        "cores": user_data.get('cores', 2),
        "current_storage_used": 0, "created_at": datetime.now().isoformat()}
    save_servers(servers)
    get_server_folder(server_id)
    return redirect(url_for('terminal', server_id=server_id))

@app.route('/terminal/<server_id>')
def terminal(server_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    users = load_users()
    user_data = users.get(session['user'], {})
    if is_account_expired(user_data):
        return redirect(url_for('login', error='expired'))
    servers = load_servers()
    if server_id not in servers or servers[server_id]['owner'] != session['user']:
        return "Unauthorized access", 403
    server_data = servers[server_id]
    folder = get_server_folder(server_id)
    uploaded_files = os.listdir(folder) if os.path.exists(folder) else []
    folder_size = get_real_disk_usage(server_id)
    cpu_speed = calculate_speed(server_data.get('cpu_type', user_data.get('cpu', 'Snapdragon')))
    remaining_time = calculate_remaining_time(user_data.get('expiry', 'Unlimited'))
    
    return render_template('terminal.html',
                         server_id=server_id, 
                         csrf_token=generate_csrf_token(),
                         server_name=server_data.get('name', 'Unknown'),
                         status=server_data.get('status', 'stopped'),
                         cpu_type=server_data.get('cpu_type', user_data.get('cpu', 'Snapdragon')),
                         cpu_speed=cpu_speed,
                         ram_allocated=server_data.get('ram', user_data.get('ram', '4 GB')),
                         storage_total=server_data.get('storage', user_data.get('storage', '50 GB')),
                         storage_used=f"{folder_size} MB",
                         logs=server_data.get('logs', [])[-50:],
                         uploaded_files=uploaded_files,
                         role=session.get('role', 'user'),
                         user=session['user'],
                         remaining_time=remaining_time)

# ========== ADMIN PANEL ==========
@app.route('/admin')
def admin_panel():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    users = load_users()
    servers = load_servers()
    banned_ips = load_banned_ips()
    packages = load_packages()
    custom_orders = load_custom_orders()
    blocked_countries = load_blocked_countries()
    return render_template('admin.html', users=users, servers=servers, banned_ips=banned_ips,
                         packages=packages, custom_orders=custom_orders, blocked_countries=blocked_countries,
                         csrf_token=generate_csrf_token())

@app.route('/admin/unban_ip/<ip>')
def unban_ip(ip):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    banned = load_banned_ips()
    if ip in banned:
        del banned[ip]
        save_banned_ips(banned)
    return redirect(url_for('admin_panel'))

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    cpu = request.form.get('cpu', '')
    ram = request.form.get('ram', '')
    storage = request.form.get('storage', '')
    cores = request.form.get('cores', '2')
    expiry = request.form.get('expiry', '')
    
    if expiry and expiry != "Unlimited":
        expiry_date = parse_expiry_date(expiry)
        if expiry_date:
            expiry = expiry_date.strftime('%Y-%m-%d')
        else:
            expiry = "Unlimited"
    
    users = load_users()
    users[username] = {"password": password, "role": "user", "cpu": cpu,
        "ram": ram, "storage": storage, "cores": int(cores),
        "expiry": expiry if expiry else "Unlimited",
        "created_at": datetime.now().isoformat()}
    save_users(users)
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<username>')
def delete_user(username):
    if username == "admin":
        return "Cannot delete admin"
    users = load_users()
    if username in users:
        servers = load_servers()
        servers_to_delete = [sid for sid, s in servers.items() if s.get('owner') == username]
        for sid in servers_to_delete:
            folder = get_server_folder(sid)
            if os.path.exists(folder):
                shutil.rmtree(folder)
            del servers[sid]
        save_servers(servers)
        del users[username]
        save_users(users)
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_custom_order/<order_id>')
def delete_custom_order(order_id):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    orders = load_custom_orders()
    orders = [o for o in orders if o.get('id') != order_id]
    save_custom_orders(orders)
    return redirect(url_for('admin_panel'))

@app.route('/admin/blocked_countries')
def admin_blocked_countries():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    blocked = load_blocked_countries()
    return render_template('blocked_countries.html', blocked=blocked.get('blocked', []), csrf_token=generate_csrf_token())

@app.route('/admin/add_blocked_country', methods=['POST'])
def add_blocked_country():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    country = request.form.get('country', '').upper()
    blocked = load_blocked_countries()
    if 'blocked' not in blocked:
        blocked['blocked'] = []
    if country and country not in blocked['blocked']:
        blocked['blocked'].append(country)
        save_blocked_countries(blocked)
    return redirect(url_for('admin_blocked_countries'))

@app.route('/admin/remove_blocked_country/<country>')
def remove_blocked_country(country):
    if 'user' not in session or session.get('role') != 'admin':
        return "Access Denied", 403
    blocked = load_blocked_countries()
    if country in blocked.get('blocked', []):
        blocked['blocked'].remove(country)
        save_blocked_countries(blocked)
    return redirect(url_for('admin_blocked_countries'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# For Render.com compatibility
if __name__ != '__main__':
    # When running on Render, use gunicorn
    pass

if __name__ == '__main__':
    os.makedirs(os.path.join(BASE_DIR, 'templates'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'servers'), exist_ok=True)
    
    print("=" * 60)
    print("HOST X SERVER MANAGEMENT SYSTEM")
    print("=" * 60)
    print(f"Default Admin: admin / admin123")
    print(f"Server running on port 5000")
    print("=" * 60)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
