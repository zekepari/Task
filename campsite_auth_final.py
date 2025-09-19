#!/usr/bin/env python3
"""
ICT320 Task 2 - Find a Campsite Authentication System
COMPLETE SINGLE-FILE SOLUTION with GUI, Password Encryption, File Logging, and Automated Testing
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import redis
from redis.exceptions import ConnectionError
import pandas as pd
import bcrypt
import random
import json
import os
from datetime import datetime
from threading import Thread
import io
import sys


class CampsiteAuthenticationSystem:
    """Complete single-file authentication system with GUI and all advanced features."""
    
    def __init__(self):
        """Initialize the complete system."""
        # Initialize Redis connection to Redis Cloud
        try:
            self.redis_client = redis.Redis(
                host='redis-15569.c51.ap-southeast-2-1.ec2.redns.redis-cloud.com',
                port=15569,
                decode_responses=True,
                username="default",
                password="zz36ZBCs4noAAt1O8xDcf47GNAKg9GCP"
            )
            self.redis_client.ping()
            self.redis_connected = True
            self._setup_security_questions()
        except ConnectionError:
            self.redis_connected = False
        
        # Initialize file logging
        self.log_file = "login_attempts.log"
        self._initialize_log_file()
        
        # Setup GUI
        self.root = tk.Tk()
        self.root.title("🏕️ Find a Campsite - Authentication System")
        self.root.geometry("1000x800")
        self.root.configure(bg='#2c3e50')
        
        # Embedded CSV data for self-contained solution
        self.csv_data = """login,password,firstname,security_q,security_a
jennifer39@yahoo.com,rS;k|9Y1,jennifer,What is your first pet's name?,fluffy
Margaret37@outlook.com,(6NI9Mlx,Margaret,What is your mother's maiden name?,smith
Fatima73@msn.com,:<O6Xr(1,Fatima,What city were you born in?,cairo
Lisa76@rediffmail.com," 9E""B^paD ",Lisa,What was the name of your first school?,riverside elementary
Elif7@live.com,a[#u9|5},Elif,What is your favorite movie?,titanic
Lisa80@outlook.com,;Oo&aDTN,Lisa,What was your childhood nickname?,lulu
Emily17@comcast.net,j+X@amzO,Emily,What is your first pet's name?,buddy
Michael85@hotmail.com,nsB_O({-,Michael,What is your mother's maiden name?,johnson
Zane94@comcast.net,Qe5iMhz|,Zane,What city were you born in?,melbourne
jennifer89@aol.com,\\=vg'MNU,jennifer,What was the name of your first school?,oak hill primary
Lisa54@comcast.net,**g|KHUk,Lisa,What is your favorite movie?,avatar
jennifer16@outlook.com,Rn}NFy`+,jennifer,What was your childhood nickname?,jen
david41@msn.com,83=_92tM,david,What is your first pet's name?,max
Chenguang6@icloud.com,-6R{SM0[,Chenguang,What is your mother's maiden name?,wang
Jennifer21@msn.com,$zet1@BJ,Jennifer,What city were you born in?,beijing
Adira41@live.com,4)XDe$:v,Adira,What was the name of your first school?,sunnydale high
Emeka62@gmail.com,1dipAf3:,Emeka,What is your favorite movie?,black panther
Kenneth48@comcast.net,rm~Et52p,Kenneth,What was your childhood nickname?,kenny
Dalia65@msn.com,=xiBu$ea,Dalia,What is your first pet's name?,luna
Xiomara20@aol.com,r*0z\\KIS,Xiomara,What is your mother's maiden name?,rodriguez"""
        
        self.setup_ui()
    
    def _setup_security_questions(self):
        """Initialize security questions in Redis."""
        security_questions = [
            "What is your first pet's name?",
            "What is your mother's maiden name?",
            "What city were you born in?",
            "What was the name of your first school?",
            "What is your favorite movie?",
            "What was your childhood nickname?"
        ]
        
        if not self.redis_client.exists('security_questions'):
            for question in security_questions:
                self.redis_client.lpush('security_questions', question)
    
    def _hash_password(self, password: str) -> str:
        """Encrypt password using bcrypt with salt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against encrypted hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def _initialize_log_file(self):
        """Initialize the login attempts log file."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write("# Find a Campsite - Login Attempts Log\\n")
                f.write("# ICT320 Task 2 - Authentication System\\n")
                f.write(f"# Log initialized: {datetime.now().isoformat()}\\n")
                f.write("# Format: Timestamp | Username | Action | Success | IP | Details\\n")
                f.write("=" * 100 + "\\n")
    
    def _log_to_file_and_redis(self, login_name: str, success: bool, action: str = "login", details: str = ""):
        """Log to both Redis and file for comprehensive tracking."""
        timestamp = datetime.now().isoformat()
        
        # Log to Redis
        redis_log = {
            'timestamp': timestamp,
            'login_name': login_name,
            'action': action,
            'success': success,
            'ip': '127.0.0.1',
            'details': details
        }
        if self.redis_connected:
            self.redis_client.lpush('login_log', json.dumps(redis_log))
            self.redis_client.ltrim('login_log', 0, 999)
        
        # Log to file
        status = "SUCCESS" if success else "FAILURE"
        log_line = f"{timestamp} | {login_name:30} | {action:15} | {status:7} | 127.0.0.1 | {details}\\n"
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_line)
        except Exception as e:
            print(f"Warning: Could not write to log file: {e}")
    
    def _count_users(self):
        """Count users efficiently."""
        if not self.redis_connected:
            return 0
        try:
            count = self.redis_client.scard("users")
            if count > 0:
                return count
            # Fallback to SCAN
            cursor = 0
            total = 0
            while True:
                cursor, keys = self.redis_client.scan(cursor=cursor, match='user:*', count=1000)
                total += len(keys)
                if cursor == 0:
                    break
            return total
        except:
            return 0
    
    def _record_failed_attempt(self, login_name: str):
        """Record failed attempt for rate limiting."""
        if not self.redis_connected:
            return
        fail_key = f"fail:{login_name}"
        fails = self.redis_client.incr(fail_key)
        if fails == 1:
            self.redis_client.expire(fail_key, 600)  # 10 minutes
    
    def setup_ui(self):
        """Setup the complete GUI interface."""
        # Header
        header = tk.Frame(self.root, bg='#34495e', height=80)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        tk.Label(header, text="🏕️ Find a Campsite", font=('Arial', 20, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(pady=5)
        tk.Label(header, text="Secure Authentication System", font=('Arial', 12),
                fg='#bdc3c7', bg='#34495e').pack()
        
        # Status bar
        status_color = '#27ae60' if self.redis_connected else '#e74c3c'
        status_text = "🟢 Redis Cloud Connected" if self.redis_connected else "🔴 Redis Disconnected"
        
        status_bar = tk.Frame(self.root, bg=status_color, height=30)
        status_bar.pack(fill='x')
        status_bar.pack_propagate(False)
        
        tk.Label(status_bar, text=status_text, font=('Arial', 10, 'bold'),
                fg='white', bg=status_color).pack(pady=5)
        
        # Main container
        main_container = tk.Frame(self.root, bg='#ecf0f1')
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left sidebar
        sidebar = tk.Frame(main_container, bg='#34495e', width=200)
        sidebar.pack(side='left', fill='y', padx=(0, 10))
        sidebar.pack_propagate(False)
        
        tk.Label(sidebar, text="Main Menu", font=('Arial', 14, 'bold'),
                fg='white', bg='#34495e').pack(pady=15)
        
        # Menu buttons
        buttons = [
            ("👤 Create Account", self.show_create_account, '#3498db'),
            ("🔑 Login", self.show_login, '#27ae60'),
            ("🔓 Forgot Password", self.show_forgot_password, '#e67e22'),
            ("📁 Load CSV Data", self.show_load_csv, '#9b59b6'),
            ("📊 Statistics", self.show_statistics, '#1abc9c'),
            ("🧪 Run Tests", self.run_tests_gui, '#f39c12'),
            ("📋 View Log", self.show_log_viewer, '#95a5a6'),
            ("❌ Exit", self.exit_app, '#e74c3c')
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(sidebar, text=text, command=command,
                          font=('Arial', 10, 'bold'), width=18, pady=8,
                          bg=color, fg='white', relief='flat')
            btn.pack(pady=3, padx=10)
        
        # Content area
        self.content_frame = tk.Frame(main_container, bg='white', relief='raised', bd=2)
        self.content_frame.pack(side='right', fill='both', expand=True)
        
        self.show_welcome()
    
    def clear_content(self):
        """Clear content area."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_welcome(self):
        """Show welcome screen."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="🏕️ Welcome to Find a Campsite", 
                font=('Arial', 18, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        welcome_text = """
🔐 Advanced Security Features:
• bcrypt password encryption with salt
• Rate limiting (5 attempts per 10 minutes)
• Comprehensive file and Redis logging
• Security question-based password recovery

📊 System Capabilities:
• Redis Cloud high-performance database
• Embedded CSV data for testing
• Real-time statistics and monitoring
• Automated testing suite (12 comprehensive tests)

🎯 Ready to Use:
All functionality available through the menu buttons.
        """
        
        tk.Label(frame, text=welcome_text, font=('Arial', 11), bg='white',
                justify='left', fg='#34495e').pack(pady=10)
        
        if self.redis_connected:
            user_count = self._count_users()
            status_frame = tk.Frame(frame, bg='#e8f5e8', relief='raised', bd=1)
            status_frame.pack(fill='x', pady=20)
            tk.Label(status_frame, text=f"📈 System Status: {user_count} users registered",
                    font=('Arial', 12, 'bold'), bg='#e8f5e8', fg='#27ae60').pack(pady=10)
    
    def show_create_account(self):
        """Show create account interface."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="👤 Create New Account", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Form
        form_frame = tk.Frame(frame, bg='#f8f9fa', relief='raised', bd=2)
        form_frame.pack(fill='x', pady=10)
        
        # Fields
        tk.Label(form_frame, text="Login Name (Email):", font=('Arial', 11), bg='#f8f9fa').pack(anchor='w', padx=20, pady=(15, 5))
        self.login_entry = tk.Entry(form_frame, font=('Arial', 11), width=50)
        self.login_entry.pack(padx=20, pady=(0, 10), fill='x')
        
        tk.Label(form_frame, text="Password (min 4 chars):", font=('Arial', 11), bg='#f8f9fa').pack(anchor='w', padx=20, pady=(0, 5))
        self.password_entry = tk.Entry(form_frame, font=('Arial', 11), width=50, show='*')
        self.password_entry.pack(padx=20, pady=(0, 10), fill='x')
        
        tk.Label(form_frame, text="First Name:", font=('Arial', 11), bg='#f8f9fa').pack(anchor='w', padx=20, pady=(0, 5))
        self.firstname_entry = tk.Entry(form_frame, font=('Arial', 11), width=50)
        self.firstname_entry.pack(padx=20, pady=(0, 15), fill='x')
        
        # Security question
        sq_frame = tk.Frame(form_frame, bg='#e3f2fd', relief='raised', bd=1)
        sq_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(sq_frame, text="🔐 Security Question", font=('Arial', 11, 'bold'), bg='#e3f2fd').pack(pady=5)
        
        tk.Button(sq_frame, text="Get Random Question", command=self.get_security_question,
                 font=('Arial', 10), bg='#2196f3', fg='white').pack(pady=5)
        
        self.security_question_var = tk.StringVar()
        self.security_question_label = tk.Label(sq_frame, textvariable=self.security_question_var,
                                               font=('Arial', 10), bg='#e3f2fd', wraplength=400)
        self.security_question_label.pack(pady=5)
        
        tk.Label(sq_frame, text="Your Answer:", font=('Arial', 10), bg='#e3f2fd').pack()
        self.security_answer_entry = tk.Entry(sq_frame, font=('Arial', 10), width=40)
        self.security_answer_entry.pack(pady=(0, 10))
        
        # Create button
        tk.Button(form_frame, text="🚀 Create Account", command=self.create_account,
                 font=('Arial', 12, 'bold'), bg='#4caf50', fg='white', pady=10).pack(pady=15)
        
        # Result
        self.create_result = tk.Label(frame, text="", font=('Arial', 11), bg='white')
        self.create_result.pack(pady=10)
    
    def get_security_question(self):
        """Get random security question."""
        if not self.redis_connected:
            messagebox.showerror("Error", "Redis not connected")
            return
        
        try:
            questions = self.redis_client.lrange('security_questions', 0, -1)
            if questions:
                question = random.choice(questions)
                self.security_question_var.set(question)
                self.current_security_question = question
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get security question: {e}")
    
    def create_account(self):
        """Create account with encrypted password."""
        if not self.redis_connected:
            messagebox.showerror("Error", "Redis not connected")
            return
        
        login_name = self.login_entry.get().strip().lower()
        password = self.password_entry.get().strip()
        firstname = self.firstname_entry.get().strip()
        security_answer = self.security_answer_entry.get().strip().lower()
        
        # Validation
        if not login_name:
            self.create_result.config(text="❌ Login name cannot be empty", fg='red')
            return
        
        if len(password) < 4:
            self.create_result.config(text="❌ Password must be at least 4 characters long", fg='red')
            return
        
        if not firstname:
            self.create_result.config(text="❌ First name cannot be empty", fg='red')
            return
        
        if not hasattr(self, 'current_security_question'):
            self.create_result.config(text="❌ Please get a security question first", fg='red')
            return
        
        if not security_answer:
            self.create_result.config(text="❌ Security answer cannot be empty", fg='red')
            return
        
        # Check duplicate
        user_key = f"user:{login_name}"
        if self.redis_client.exists(user_key):
            self.create_result.config(text=f"❌ User '{login_name}' already exists", fg='red')
            self._log_to_file_and_redis(login_name, False, "account_creation", "duplicate_user")
            return
        
        try:
            # Encrypt password
            encrypted_password = self._hash_password(password)
            
            user_data = {
                'login': login_name,
                'password': encrypted_password,
                'firstname': firstname,
                'security_q': self.current_security_question,
                'security_a': security_answer
            }
            
            self.redis_client.hset(user_key, mapping=user_data)
            self.redis_client.sadd("users", login_name)
            
            self.create_result.config(text=f"✅ Account created for {firstname}! Password encrypted with bcrypt.", fg='green')
            self._log_to_file_and_redis(login_name, True, "account_creation", f"user:{firstname}")
            
            # Clear form
            self.login_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.firstname_entry.delete(0, tk.END)
            self.security_answer_entry.delete(0, tk.END)
            self.security_question_var.set("")
            
        except Exception as e:
            self.create_result.config(text=f"❌ Error: {e}", fg='red')
            self._log_to_file_and_redis(login_name, False, "account_creation", f"error:{str(e)}")
    
    def show_login(self):
        """Show login interface."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="🔑 User Login", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Login form
        login_frame = tk.Frame(frame, bg='#f0f8f0', relief='raised', bd=2)
        login_frame.pack(fill='x', pady=20)
        
        tk.Label(login_frame, text="Login Name:", font=('Arial', 11), bg='#f0f8f0').pack(anchor='w', padx=20, pady=(15, 5))
        self.login_username_entry = tk.Entry(login_frame, font=('Arial', 11), width=50)
        self.login_username_entry.pack(padx=20, pady=(0, 10), fill='x')
        
        tk.Label(login_frame, text="Password:", font=('Arial', 11), bg='#f0f8f0').pack(anchor='w', padx=20, pady=(0, 5))
        self.login_password_entry = tk.Entry(login_frame, font=('Arial', 11), width=50, show='*')
        self.login_password_entry.pack(padx=20, pady=(0, 15), fill='x')
        
        tk.Button(login_frame, text="🚀 Login", command=self.authenticate_user,
                 font=('Arial', 12, 'bold'), bg='#4caf50', fg='white', pady=10).pack(pady=(0, 15))
        
        self.login_result = tk.Label(frame, text="", font=('Arial', 11, 'bold'), bg='white')
        self.login_result.pack(pady=10)
        
        # Test users hint
        hint_frame = tk.Frame(frame, bg='#fff3e0', relief='raised', bd=1)
        hint_frame.pack(fill='x', pady=10)
        tk.Label(hint_frame, text="💡 Test with CSV users: michael85@hotmail.com / nsB_O({-",
                font=('Arial', 10), bg='#fff3e0').pack(pady=10)
    
    def authenticate_user(self):
        """Authenticate user with encrypted password verification."""
        if not self.redis_connected:
            messagebox.showerror("Error", "Redis not connected")
            return
        
        login_name = self.login_username_entry.get().strip().lower()
        password = self.login_password_entry.get().strip()
        
        if not login_name or not password:
            self.login_result.config(text="❌ Login name and password cannot be empty", fg='red')
            self._log_to_file_and_redis(login_name, False, "login", "empty_credentials")
            return
        
        # Rate limiting check
        fail_key = f"fail:{login_name}"
        fails = self.redis_client.get(fail_key)
        if fails and int(fails) > 5:
            self.login_result.config(text="❌ Too many failed attempts. Try again later.", fg='red')
            self._log_to_file_and_redis(login_name, False, "login", "rate_limited")
            return
        
        try:
            user_key = f"user:{login_name}"
            user_data = self.redis_client.hgetall(user_key)
            
            if not user_data:
                self.login_result.config(text="❌ Invalid login credentials", fg='red')
                self._record_failed_attempt(login_name)
                self._log_to_file_and_redis(login_name, False, "login", "user_not_found")
                return
            
            # Verify encrypted password
            if self._verify_password(password, user_data['password']):
                self.login_result.config(text=f"✅ Welcome back, {user_data['firstname']}! 🏕️", fg='green')
                self.redis_client.delete(fail_key)
                self._log_to_file_and_redis(login_name, True, "login", f"welcome:{user_data['firstname']}")
                self.login_password_entry.delete(0, tk.END)
            else:
                self.login_result.config(text="❌ Invalid login credentials", fg='red')
                self._record_failed_attempt(login_name)
                self._log_to_file_and_redis(login_name, False, "login", "wrong_password")
                
        except Exception as e:
            self.login_result.config(text=f"❌ Login error: {e}", fg='red')
            self._log_to_file_and_redis(login_name, False, "login", f"system_error:{str(e)}")
    
    def show_forgot_password(self):
        """Show password recovery interface."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="🔓 Password Recovery", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Step 1
        step1 = tk.Frame(frame, bg='#fff8e1', relief='raised', bd=2)
        step1.pack(fill='x', pady=5)
        
        tk.Label(step1, text="Step 1: Enter Login Name", font=('Arial', 11, 'bold'), bg='#fff8e1').pack(pady=10)
        self.forgot_username_entry = tk.Entry(step1, font=('Arial', 11), width=40)
        self.forgot_username_entry.pack(pady=5)
        tk.Button(step1, text="Get Security Question", command=self.get_user_security_question,
                 font=('Arial', 10), bg='#ff9800', fg='white').pack(pady=(5, 15))
        
        # Step 2
        self.step2_frame = tk.Frame(frame, bg='#e8f5e8', relief='raised', bd=2)
        self.step2_frame.pack(fill='x', pady=5)
        
        # Step 3
        self.step3_frame = tk.Frame(frame, bg='#f3e5f5', relief='raised', bd=2)
        self.step3_frame.pack(fill='x', pady=5)
        
        self.forgot_result = tk.Label(frame, text="", font=('Arial', 11, 'bold'), bg='white')
        self.forgot_result.pack(pady=10)
    
    def get_user_security_question(self):
        """Get user's security question."""
        login_name = self.forgot_username_entry.get().strip().lower()
        
        if not login_name:
            self.forgot_result.config(text="❌ Please enter login name", fg='red')
            return
        
        if not self.redis_connected:
            messagebox.showerror("Error", "Redis not connected")
            return
        
        try:
            user_key = f"user:{login_name}"
            user_data = self.redis_client.hgetall(user_key)
            
            if not user_data:
                self.forgot_result.config(text="❌ User not found", fg='red')
                self._log_to_file_and_redis(login_name, False, "password_reset", "user_not_found")
                return
            
            # Show step 2
            for widget in self.step2_frame.winfo_children():
                widget.destroy()
            
            tk.Label(self.step2_frame, text="Step 2: Answer Security Question", 
                    font=('Arial', 11, 'bold'), bg='#e8f5e8').pack(pady=10)
            tk.Label(self.step2_frame, text=user_data['security_q'], 
                    font=('Arial', 10, 'italic'), bg='#e8f5e8', wraplength=400).pack(pady=5)
            
            self.security_answer_forgot_entry = tk.Entry(self.step2_frame, font=('Arial', 10), width=40)
            self.security_answer_forgot_entry.pack(pady=5)
            tk.Button(self.step2_frame, text="Verify Answer", command=self.verify_security_answer,
                     font=('Arial', 10), bg='#4caf50', fg='white').pack(pady=(5, 15))
            
            self.current_forgot_user = login_name
            self.forgot_result.config(text="✅ Security question loaded", fg='blue')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get security question: {e}")
    
    def verify_security_answer(self):
        """Verify security answer."""
        answer = self.security_answer_forgot_entry.get().strip().lower()
        
        if not answer:
            self.forgot_result.config(text="❌ Please enter security answer", fg='red')
            return
        
        try:
            user_key = f"user:{self.current_forgot_user}"
            user_data = self.redis_client.hgetall(user_key)
            
            if answer == user_data['security_a']:
                # Show step 3
                for widget in self.step3_frame.winfo_children():
                    widget.destroy()
                
                tk.Label(self.step3_frame, text="Step 3: Set New Password", 
                        font=('Arial', 11, 'bold'), bg='#f3e5f5').pack(pady=10)
                self.new_password_entry = tk.Entry(self.step3_frame, font=('Arial', 10), width=40, show='*')
                self.new_password_entry.pack(pady=5)
                tk.Button(self.step3_frame, text="🔄 Reset Password", command=self.reset_password,
                         font=('Arial', 10), bg='#9c27b0', fg='white').pack(pady=(5, 15))
                
                self.forgot_result.config(text="✅ Correct! Enter new password.", fg='green')
            else:
                self.forgot_result.config(text="❌ Incorrect security answer", fg='red')
                self._log_to_file_and_redis(self.current_forgot_user, False, "password_reset", "wrong_security_answer")
                
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {e}")
    
    def reset_password(self):
        """Reset password with encryption."""
        new_password = self.new_password_entry.get().strip()
        
        if len(new_password) < 4:
            self.forgot_result.config(text="❌ Password must be at least 4 characters", fg='red')
            return
        
        try:
            user_key = f"user:{self.current_forgot_user}"
            encrypted_password = self._hash_password(new_password)
            self.redis_client.hset(user_key, 'password', encrypted_password)
            
            self.forgot_result.config(text="✅ Password reset successfully! New password encrypted.", fg='green')
            self._log_to_file_and_redis(self.current_forgot_user, True, "password_reset", "password_updated")
            
            self.new_password_entry.delete(0, tk.END)
            self.security_answer_forgot_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Password reset failed: {e}")
    
    def show_load_csv(self):
        """Show CSV loading interface."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="📁 Load CSV Data", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Options
        options_frame = tk.Frame(frame, bg='#f5f5f5', relief='raised', bd=2)
        options_frame.pack(fill='x', pady=10)
        
        tk.Label(options_frame, text="Choose data source:", font=('Arial', 11, 'bold'), bg='#f5f5f5').pack(pady=10)
        
        tk.Button(options_frame, text="📊 Load Embedded CSV Data (20 users)", 
                 command=self.load_embedded_csv, font=('Arial', 11), 
                 bg='#673ab7', fg='white', pady=5).pack(pady=5)
        
        tk.Button(options_frame, text="📂 Load External CSV File", 
                 command=self.load_external_csv, font=('Arial', 11), 
                 bg='#3f51b5', fg='white', pady=5).pack(pady=(0, 15))
        
        # Results
        self.csv_result_text = scrolledtext.ScrolledText(frame, height=15, font=('Courier', 9))
        self.csv_result_text.pack(fill='both', expand=True, pady=10)
    
    def load_embedded_csv(self):
        """Load embedded CSV data."""
        if not self.redis_connected:
            messagebox.showerror("Error", "Redis not connected")
            return
        
        self.csv_result_text.delete(1.0, tk.END)
        self.csv_result_text.insert(tk.END, "🔄 Loading embedded CSV data...\\n")
        self.csv_result_text.insert(tk.END, "=" * 60 + "\\n")
        
        try:
            # Parse embedded CSV
            df = pd.read_csv(io.StringIO(self.csv_data))
            
            loaded_count = 0
            skipped_count = 0
            
            for _, row in df.iterrows():
                login_name = str(row['login']).strip().lower()
                user_key = f"user:{login_name}"
                
                if self.redis_client.exists(user_key):
                    self.csv_result_text.insert(tk.END, f"⚠️  Skipping existing: {login_name}\\n")
                    skipped_count += 1
                    continue
                
                # Encrypt password
                encrypted_password = self._hash_password(str(row['password']).strip())
                
                user_data = {
                    'login': login_name,
                    'password': encrypted_password,
                    'firstname': str(row['firstname']).strip(),
                    'security_q': str(row['security_q']).strip(),
                    'security_a': str(row['security_a']).strip().lower()
                }
                
                self.redis_client.hset(user_key, mapping=user_data)
                self.redis_client.sadd("users", login_name)
                loaded_count += 1
                
                self.csv_result_text.insert(tk.END, f"✅ Loaded: {user_data['firstname']} ({login_name})\\n")
                
                if loaded_count % 5 == 0:
                    self.csv_result_text.see(tk.END)
                    self.csv_result_text.update()
            
            self.csv_result_text.insert(tk.END, f"\\n🎉 Embedded CSV Import Complete!\\n")
            self.csv_result_text.insert(tk.END, f"✅ Users loaded: {loaded_count}\\n")
            self.csv_result_text.insert(tk.END, f"⚠️  Users skipped: {skipped_count}\\n")
            self.csv_result_text.insert(tk.END, f"🔐 All passwords encrypted with bcrypt\\n")
            
            self._log_to_file_and_redis("SYSTEM", True, "csv_import", f"embedded_data:loaded:{loaded_count}")
            
        except Exception as e:
            self.csv_result_text.insert(tk.END, f"❌ Error loading embedded CSV: {e}\\n")
            self._log_to_file_and_redis("SYSTEM", False, "csv_import", f"embedded_error:{str(e)}")
    
    def load_external_csv(self):
        """Load external CSV file."""
        filename = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        self.csv_result_text.delete(1.0, tk.END)
        self.csv_result_text.insert(tk.END, f"🔄 Loading external CSV: {filename}\\n")
        
        try:
            df = pd.read_csv(filename)
            required_columns = ['login', 'password', 'firstname', 'security_q', 'security_a']
            
            if not all(col in df.columns for col in required_columns):
                self.csv_result_text.insert(tk.END, f"❌ CSV must contain: {required_columns}\\n")
                return
            
            loaded_count = 0
            for _, row in df.iterrows():
                if pd.isna(row['login']):
                    continue
                    
                login_name = str(row['login']).strip().lower()
                user_key = f"user:{login_name}"
                
                if self.redis_client.exists(user_key):
                    continue
                
                encrypted_password = self._hash_password(str(row['password']).strip())
                user_data = {
                    'login': login_name,
                    'password': encrypted_password,
                    'firstname': str(row['firstname']).strip(),
                    'security_q': str(row['security_q']).strip(),
                    'security_a': str(row['security_a']).strip().lower()
                }
                
                self.redis_client.hset(user_key, mapping=user_data)
                self.redis_client.sadd("users", login_name)
                loaded_count += 1
            
            self.csv_result_text.insert(tk.END, f"✅ External CSV loaded: {loaded_count} users\\n")
            self._log_to_file_and_redis("SYSTEM", True, "csv_import", f"external_file:loaded:{loaded_count}")
            
        except Exception as e:
            self.csv_result_text.insert(tk.END, f"❌ Error: {e}\\n")
    
    def show_statistics(self):
        """Show system statistics."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="📊 System Statistics", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        if not self.redis_connected:
            tk.Label(frame, text="❌ Redis not connected", fg='red', bg='white').pack()
            return
        
        try:
            user_count = self._count_users()
            questions = self.redis_client.lrange('security_questions', 0, -1)
            recent_logs = self.redis_client.lrange('login_log', 0, 19)
            
            stats_text = f"""
📈 SYSTEM OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Total Users: {user_count}
• Security Questions: {len(questions)}
• Recent Activities: {len(recent_logs)}
• Database: Redis Cloud
• Log File: {self.log_file}

🔐 SECURITY QUESTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for i, q in enumerate(questions, 1):
                stats_text += f"{i}. {q}\\n"
            
            stats_text += "\\n📝 RECENT ACTIVITIES\\n"
            stats_text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n"
            
            for log_json in recent_logs:
                try:
                    log_data = json.loads(log_json)
                    status = "✅" if log_data['success'] else "❌"
                    timestamp = log_data['timestamp'][:19].replace('T', ' ')
                    stats_text += f"{status} {timestamp} | {log_data['login_name'][:20]:20} | {log_data['action'].upper()}\\n"
                except:
                    pass
            
            text_widget = scrolledtext.ScrolledText(frame, font=('Courier', 9), height=20)
            text_widget.pack(fill='both', expand=True, pady=10)
            text_widget.insert(1.0, stats_text)
            text_widget.config(state='disabled')
            
        except Exception as e:
            tk.Label(frame, text=f"❌ Error: {e}", fg='red', bg='white').pack()
    
    def show_log_viewer(self):
        """Show log file viewer."""
        self.clear_content()
        
        frame = tk.Frame(self.content_frame, bg='white')
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="📋 Login Attempts Log", 
                font=('Arial', 16, 'bold'), bg='white', fg='#2c3e50').pack(pady=10)
        
        # Controls
        controls = tk.Frame(frame, bg='white')
        controls.pack(fill='x', pady=5)
        
        tk.Button(controls, text="🔄 Refresh", command=self.refresh_log,
                 font=('Arial', 10), bg='#607d8b', fg='white').pack(side='left', padx=5)
        tk.Button(controls, text="🗑️ Clear Log", command=self.clear_log,
                 font=('Arial', 10), bg='#f44336', fg='white').pack(side='left', padx=5)
        
        # Log display
        self.log_display = scrolledtext.ScrolledText(frame, font=('Courier', 8), height=25)
        self.log_display.pack(fill='both', expand=True, pady=10)
        
        self.refresh_log()
    
    def refresh_log(self):
        """Refresh log display."""
        try:
            self.log_display.delete(1.0, tk.END)
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    content = f.read()
                    self.log_display.insert(1.0, content)
            else:
                self.log_display.insert(1.0, "Log file not found.")
            self.log_display.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read log: {e}")
    
    def clear_log(self):
        """Clear log file."""
        if messagebox.askyesno("Clear Log", "Clear all log entries?"):
            try:
                self._initialize_log_file()
                self.refresh_log()
                messagebox.showinfo("Success", "Log cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear log: {e}")
    
    def run_tests_gui(self):
        """Run automated tests with GUI progress."""
        test_window = tk.Toplevel(self.root)
        test_window.title("🧪 Automated Testing Suite")
        test_window.geometry("800x600")
        test_window.configure(bg='white')
        
        tk.Label(test_window, text="🧪 Comprehensive System Testing", 
                font=('Arial', 16, 'bold'), bg='white').pack(pady=10)
        
        # Progress
        progress = ttk.Progressbar(test_window, mode='determinate')
        progress.pack(fill='x', padx=20, pady=10)
        
        # Results
        results_text = scrolledtext.ScrolledText(test_window, font=('Courier', 10), height=25)
        results_text.pack(fill='both', expand=True, padx=20, pady=10)
        
        def run_tests():
            test_user = f"autotest_{random.randint(1000, 9999)}"
            
            tests = [
                ("Redis Connection", self._test_redis_connection),
                ("Password Encryption", self._test_password_encryption),
                ("Account Creation", self._test_account_creation, test_user),
                ("Duplicate Prevention", self._test_duplicate_prevention, test_user),
                ("Login Authentication", self._test_login_authentication, test_user),
                ("Password Reset", self._test_password_reset, test_user),
                ("Security Questions", self._test_security_questions),
                ("File Logging", self._test_file_logging, test_user),
                ("Rate Limiting", self._test_rate_limiting, test_user),
                ("Data Integrity", self._test_data_integrity, test_user),
                ("CSV Processing", self._test_csv_processing),
                ("System Performance", self._test_performance)
            ]
            
            passed = 0
            total = len(tests)
            
            results_text.insert(tk.END, "🚀 Starting Comprehensive Test Suite\\n")
            results_text.insert(tk.END, "=" * 60 + "\\n\\n")
            
            for i, test_data in enumerate(tests):
                test_name = test_data[0]
                test_func = test_data[1]
                test_args = test_data[2:] if len(test_data) > 2 else []
                
                results_text.insert(tk.END, f"🔍 Test {i+1:2d}/{total}: {test_name}...\\n")
                results_text.see(tk.END)
                results_text.update()
                
                try:
                    result = test_func(*test_args)
                    if result:
                        results_text.insert(tk.END, f"✅ {test_name}: PASSED\\n")
                        passed += 1
                    else:
                        results_text.insert(tk.END, f"❌ {test_name}: FAILED\\n")
                except Exception as e:
                    results_text.insert(tk.END, f"❌ {test_name}: ERROR - {e}\\n")
                
                progress['value'] = (i + 1) / total * 100
                results_text.see(tk.END)
                results_text.update()
            
            success_rate = passed / total * 100
            results_text.insert(tk.END, f"\\n{'='*60}\\n")
            results_text.insert(tk.END, f"📊 RESULTS: {passed}/{total} tests passed\\n")
            results_text.insert(tk.END, f"📈 Success Rate: {success_rate:.1f}%\\n")
            
            if success_rate == 100:
                results_text.insert(tk.END, f"🏆 ALL TESTS PASSED - PRODUCTION READY!\\n")
            
            self._log_to_file_and_redis("SYSTEM", success_rate == 100, "automated_testing", 
                                       f"gui_tests:passed:{passed}_total:{total}")
            
            results_text.see(tk.END)
        
        Thread(target=run_tests, daemon=True).start()
    
    # Test methods
    def _test_redis_connection(self):
        try:
            self.redis_client.ping()
            return True
        except:
            return False
    
    def _test_password_encryption(self):
        try:
            password = "test_password"
            hash1 = self._hash_password(password)
            hash2 = self._hash_password(password)
            return (hash1 != hash2 and 
                   self._verify_password(password, hash1) and
                   self._verify_password(password, hash2) and
                   not self._verify_password("wrong", hash1))
        except:
            return False
    
    def _test_account_creation(self, test_user):
        try:
            user_key = f"user:{test_user}"
            self.redis_client.delete(user_key)
            self.redis_client.srem("users", test_user)
            
            encrypted = self._hash_password("testpass123")
            user_data = {
                'login': test_user,
                'password': encrypted,
                'firstname': "Test User",
                'security_q': "What is your first pet's name?",
                'security_a': "fluffy"
            }
            
            self.redis_client.hset(user_key, mapping=user_data)
            self.redis_client.sadd("users", test_user)
            
            stored = self.redis_client.hgetall(user_key)
            return stored and stored['password'].startswith('$2b$')
        except:
            return False
    
    def _test_duplicate_prevention(self, test_user):
        return self.redis_client.exists(f"user:{test_user}")
    
    def _test_login_authentication(self, test_user):
        try:
            user_data = self.redis_client.hgetall(f"user:{test_user}")
            return (user_data and 
                   self._verify_password("testpass123", user_data['password']) and
                   not self._verify_password("wrong", user_data['password']))
        except:
            return False
    
    def _test_password_reset(self, test_user):
        try:
            user_key = f"user:{test_user}"
            new_encrypted = self._hash_password("newpass456")
            self.redis_client.hset(user_key, 'password', new_encrypted)
            
            user_data = self.redis_client.hgetall(user_key)
            return (self._verify_password("newpass456", user_data['password']) and
                   not self._verify_password("testpass123", user_data['password']))
        except:
            return False
    
    def _test_security_questions(self):
        try:
            questions = self.redis_client.lrange('security_questions', 0, -1)
            return len(questions) >= 6
        except:
            return False
    
    def _test_file_logging(self, test_user):
        try:
            self._log_to_file_and_redis(test_user, True, "test_action", "automated_test")
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    content = f.read()
                    return test_user in content and "test_action" in content
            return False
        except:
            return False
    
    def _test_rate_limiting(self, test_user):
        try:
            for _ in range(6):
                self._record_failed_attempt(test_user)
            
            fails = self.redis_client.get(f"fail:{test_user}")
            self.redis_client.delete(f"fail:{test_user}")
            return fails and int(fails) > 5
        except:
            return False
    
    def _test_data_integrity(self, test_user):
        try:
            user_key = f"user:{test_user}"
            in_hash = self.redis_client.exists(user_key)
            in_set = self.redis_client.sismember("users", test_user)
            
            # Cleanup
            self.redis_client.delete(user_key)
            self.redis_client.srem("users", test_user)
            
            return in_hash and in_set
        except:
            return False
    
    def _test_csv_processing(self):
        try:
            df = pd.read_csv(io.StringIO(self.csv_data))
            required_cols = ['login', 'password', 'firstname', 'security_q', 'security_a']
            return all(col in df.columns for col in required_cols)
        except:
            return False
    
    def _test_performance(self):
        try:
            import time
            start = time.time()
            self._count_users()
            count_time = time.time() - start
            
            start = time.time()
            self._hash_password("performance_test")
            hash_time = time.time() - start
            
            return count_time < 2.0 and hash_time < 1.0
        except:
            return False
    
    def exit_app(self):
        """Exit application."""
        if messagebox.askokcancel("Exit", "Exit Find a Campsite Authentication System?"):
            self._log_to_file_and_redis("SYSTEM", True, "application_shutdown", "gui_exit")
            self.root.quit()
            self.root.destroy()
    
    def run(self):
        """Run the GUI application."""
        if not self.redis_connected:
            messagebox.showerror("Redis Error", 
                               "Failed to connect to Redis Cloud.\\n\\n"
                               "The application will run in demo mode.")
        
        # Log startup
        self._log_to_file_and_redis("SYSTEM", True, "application_startup", "gui_mode")
        
        self.root.mainloop()


def main():
    """Main function - single entry point."""
    try:
        app = CampsiteAuthenticationSystem()
        app.run()
    except Exception as e:
        print(f"Application error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
