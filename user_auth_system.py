#!/usr/bin/env python3
"""
ICT320 Task 2 - User Authentication System with Redis
A complete user management system with Redis backend.
"""

import redis
import pandas as pd
import bcrypt
import random
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from getpass import getpass


class UserAuthSystem:
    """Main class for user authentication system using Redis."""
    
    def __init__(self, redis_host=None, redis_port=None, redis_db=None):
        """Initialize Redis connection and setup security questions."""
        # Use environment variables or defaults
        redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        redis_port = redis_port or int(os.getenv("REDIS_PORT", "6379"))
        redis_db = redis_db or int(os.getenv("REDIS_DB", "0"))
        
        try:
            self.redis_client = redis.Redis(
                host=redis_host, 
                port=redis_port, 
                db=redis_db, 
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
            print("✓ Connected to Redis successfully")
            self._setup_security_questions()
        except redis.ConnectionError as e:
            raise RuntimeError("Failed to connect to Redis") from e
    
    def _setup_security_questions(self):
        """Initialize security questions in Redis if not already present."""
        security_questions = [
            "What is your first pet's name?",
            "What is your mother's maiden name?",
            "What city were you born in?",
            "What was the name of your first school?",
            "What is your favorite movie?",
            "What was your childhood nickname?"
        ]
        
        # Only add if the list doesn't exist
        if not self.redis_client.exists('security_questions'):
            for question in security_questions:
                self.redis_client.lpush('security_questions', question)
            print("✓ Security questions initialized")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt for secure storage."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def _log_login_attempt(self, login_name: str, success: bool, action: str = "login"):
        """Log login attempts to Redis list."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'login_name': login_name,
            'action': action,
            'success': success,
            'ip': '127.0.0.1'  # Could be enhanced to get real IP
        }
        self.redis_client.lpush('login_log', json.dumps(log_entry))
        # Keep only last 1000 log entries
        self.redis_client.ltrim('login_log', 0, 999)
    
    def create_account(self) -> bool:
        """Create a new user account."""
        print("\n=== CREATE ACCOUNT ===")
        
        # Get user input
        login_name = input("Enter login name: ").strip().lower()
        if not login_name:
            print("✗ Login name cannot be empty")
            return False
        
        # Check if user already exists
        user_key = f"user:{login_name}"
        if self.redis_client.exists(user_key):
            print(f"✗ User '{login_name}' already exists")
            return False
        
        password = getpass("Enter password: ").strip()
        if len(password) < 4:
            print("✗ Password must be at least 4 characters long")
            return False
        
        firstname = input("Enter first name: ").strip()
        if not firstname:
            print("✗ First name cannot be empty")
            return False
        
        # Get random security question
        questions = self.redis_client.lrange('security_questions', 0, -1)
        if not questions:
            print("✗ No security questions available")
            return False
        
        security_question = random.choice(questions)
        print(f"\nSecurity Question: {security_question}")
        security_answer = input("Your answer: ").strip().lower()
        
        if not security_answer:
            print("✗ Security answer cannot be empty")
            return False
        
        # Hash password and store user data
        hashed_password = self._hash_password(password)
        
        user_data = {
            'login': login_name,
            'password': hashed_password,
            'firstname': firstname,
            'security_q': security_question,
            'security_a': security_answer.lower()  # Store in lowercase for case-insensitive comparison
        }
        
        # Store in Redis hash
        self.redis_client.hset(user_key, mapping=user_data)
        # Add to users set for O(1) counting
        self.redis_client.sadd("users", login_name)
        
        print(f"✓ Account created successfully for {firstname}!")
        self._log_login_attempt(login_name, True, "account_created")
        return True
    
    def login(self) -> bool:
        """Authenticate user login with basic rate limiting."""
        print("\n=== LOGIN ===")
        
        login_name = input("Enter login name: ").strip().lower()
        password = getpass("Enter password: ").strip()
        
        if not login_name or not password:
            print("✗ Login name and password cannot be empty")
            self._log_login_attempt(login_name, False, "login")
            return False
        
        # Basic rate limiting
        fail_key = f"fail:{login_name}"
        fails = self.redis_client.get(fail_key)
        if fails and int(fails) > 5:
            print("✗ Too many failed attempts. Try again later.")
            return False
        
        user_key = f"user:{login_name}"
        user_data = self.redis_client.hgetall(user_key)
        
        if not user_data:
            print("✗ Invalid login credentials")
            self._record_failed_attempt(login_name)
            self._log_login_attempt(login_name, False, "login")
            return False
        
        # Verify password
        if self._verify_password(password, user_data['password']):
            print(f"✓ Welcome back, {user_data['firstname']}!")
            # Clear failed attempts on success
            self.redis_client.delete(fail_key)
            self._log_login_attempt(login_name, True, "login")
            return True
        else:
            print("✗ Invalid login credentials")
            self._record_failed_attempt(login_name)
            self._log_login_attempt(login_name, False, "login")
            return False
    
    def _record_failed_attempt(self, login_name: str):
        """Record failed login attempt for rate limiting."""
        fail_key = f"fail:{login_name}"
        fails = self.redis_client.incr(fail_key)
        if fails == 1:
            self.redis_client.expire(fail_key, 600)  # 10 minutes
    
    def forgot_password(self) -> bool:
        """Reset password using security question."""
        print("\n=== FORGOT PASSWORD ===")
        
        login_name = input("Enter your login name: ").strip().lower()
        
        if not login_name:
            print("✗ Login name cannot be empty")
            return False
        
        user_key = f"user:{login_name}"
        user_data = self.redis_client.hgetall(user_key)
        
        if not user_data:
            print("✗ User not found")
            self._log_login_attempt(login_name, False, "password_reset")
            return False
        
        # Ask security question
        print(f"\nSecurity Question: {user_data['security_q']}")
        answer = input("Your answer: ").strip().lower()
        
        if answer == user_data['security_a']:
            # Allow password reset
            new_password = getpass("Enter new password: ").strip()
            if len(new_password) < 4:
                print("✗ Password must be at least 4 characters long")
                return False
            
            # Update password
            hashed_password = self._hash_password(new_password)
            self.redis_client.hset(user_key, 'password', hashed_password)
            
            print("✓ Password updated successfully!")
            self._log_login_attempt(login_name, True, "password_reset")
            return True
        else:
            print("✗ Incorrect security answer")
            self._log_login_attempt(login_name, False, "password_reset")
            return False
    
    def load_csv_data(self, csv_file: str) -> bool:
        """Load initial user data from CSV file."""
        try:
            print(f"\n=== LOADING CSV DATA: {csv_file} ===")
            df = pd.read_csv(csv_file)
            
            required_columns = ['login', 'password', 'firstname', 'security_q', 'security_a']
            if not all(col in df.columns for col in required_columns):
                print(f"✗ CSV must contain columns: {required_columns}")
                return False
            
            loaded_count = 0
            for _, row in df.iterrows():
                user_key = f"user:{row['login'].strip().lower()}"
                
                # Skip if user already exists
                if self.redis_client.exists(user_key):
                    print(f"⚠ User '{row['login']}' already exists, skipping")
                    continue
                
                # Hash password and prepare data
                login_name = row['login'].strip().lower()
                user_data = {
                    'login': login_name,
                    'password': self._hash_password(str(row['password']).strip()),
                    'firstname': row['firstname'].strip(),
                    'security_q': row['security_q'].strip(),
                    'security_a': str(row['security_a']).strip().lower()
                }
                
                self.redis_client.hset(user_key, mapping=user_data)
                # Add to users set
                self.redis_client.sadd("users", login_name)
                loaded_count += 1
            
            print(f"✓ Loaded {loaded_count} users from CSV")
            return True
            
        except FileNotFoundError:
            print(f"✗ CSV file '{csv_file}' not found")
            return False
        except Exception as e:
            print(f"✗ Error loading CSV: {e}")
            return False
    
    def _count_users(self):
        """Count users using SCAN instead of KEYS for better performance."""
        cursor = 0
        total = 0
        while True:
            cursor, keys = self.redis_client.scan(cursor=cursor, match='user:*', count=1000)
            total += len(keys)
            if cursor == 0:
                break
        return total
    
    def show_stats(self):
        """Display system statistics."""
        print("\n=== SYSTEM STATISTICS ===")
        
        # Count users - prefer users set if available, fallback to SCAN
        try:
            total_users = self.redis_client.scard("users")
            if total_users == 0:  # Fallback if set doesn't exist yet
                total_users = self._count_users()
        except:
            total_users = self._count_users()
        
        print(f"Total users: {total_users}")
        
        # Show recent login attempts
        log_entries = self.redis_client.lrange('login_log', 0, 4)  # Last 5 entries
        if log_entries:
            print("\nRecent login attempts:")
            for entry in log_entries:
                log_data = json.loads(entry)
                status = "✓" if log_data['success'] else "✗"
                print(f"  {status} {log_data['timestamp'][:19]} - {log_data['login_name']} ({log_data['action']})")
        
        # Show security questions
        questions = self.redis_client.lrange('security_questions', 0, -1)
        print(f"\nSecurity questions available: {len(questions)}")
    
    def run_tests(self):
        """Run comprehensive test cases."""
        print("\n=== RUNNING TESTS ===")
        
        # Test 1: Account creation (success)
        print("\n1. Testing account creation (success)...")
        test_user = f"testuser_{random.randint(1000, 9999)}"
        
        # Simulate user input for testing
        original_input = input
        test_inputs = [test_user, "testpass123", "Test User", "test answer"]
        input_iter = iter(test_inputs)
        
        def mock_input(prompt):
            return next(input_iter)
        
        # Temporarily replace input function
        import builtins
        builtins.input = mock_input
        
        try:
            success = self.create_account()
            print(f"✓ Account creation test: {'PASSED' if success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        # Test 2: Account creation (duplicate)
        print("\n2. Testing duplicate account creation...")
        test_inputs = [test_user, "testpass123", "Test User", "test answer"]
        input_iter = iter(test_inputs)
        builtins.input = mock_input
        
        try:
            success = self.create_account()
            print(f"✓ Duplicate account test: {'PASSED' if not success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        # Test 3: Login (success)
        print("\n3. Testing login (success)...")
        test_inputs = [test_user, "testpass123"]
        input_iter = iter(test_inputs)
        builtins.input = mock_input
        
        try:
            success = self.login()
            print(f"✓ Login success test: {'PASSED' if success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        # Test 4: Login (failure)
        print("\n4. Testing login (failure)...")
        test_inputs = [test_user, "wrongpassword"]
        input_iter = iter(test_inputs)
        builtins.input = mock_input
        
        try:
            success = self.login()
            print(f"✓ Login failure test: {'PASSED' if not success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        # Test 5: Forgot password (success)
        print("\n5. Testing forgot password (success)...")
        test_inputs = [test_user, "test answer", "newpassword123"]
        input_iter = iter(test_inputs)
        builtins.input = mock_input
        
        try:
            success = self.forgot_password()
            print(f"✓ Forgot password success test: {'PASSED' if success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        # Test 6: Forgot password (failure)
        print("\n6. Testing forgot password (failure)...")
        test_inputs = [test_user, "wrong answer", "newpassword123"]
        input_iter = iter(test_inputs)
        builtins.input = mock_input
        
        try:
            success = self.forgot_password()
            print(f"✓ Forgot password failure test: {'PASSED' if not success else 'FAILED'}")
        finally:
            builtins.input = original_input
        
        print("\n=== TESTS COMPLETED ===")
    
    def main_menu(self):
        """Main program loop with menu options."""
        print("\n" + "="*50)
        print("    USER AUTHENTICATION SYSTEM")
        print("="*50)
        
        while True:
            print("\n--- MAIN MENU ---")
            print("1. Create Account")
            print("2. Login")
            print("3. Forgot Password")
            print("4. Load CSV Data")
            print("5. Show Statistics")
            print("6. Run Tests")
            print("7. Exit")
            
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == '1':
                self.create_account()
            elif choice == '2':
                self.login()
            elif choice == '3':
                self.forgot_password()
            elif choice == '4':
                csv_file = input("Enter CSV file path: ").strip()
                self.load_csv_data(csv_file)
            elif choice == '5':
                self.show_stats()
            elif choice == '6':
                self.run_tests()
            elif choice == '7':
                print("\n✓ Goodbye!")
                break
            else:
                print("✗ Invalid option. Please select 1-7.")


def main():
    """Main function to run the user authentication system."""
    print("ICT320 Task 2 - User Authentication System")
    print("==========================================")
    
    try:
        auth_system = UserAuthSystem()
        auth_system.main_menu()
    except RuntimeError as e:
        print(f"✗ {e}. Start Redis and try again (e.g., `redis-server`).")
        print("  Test connection: redis-cli ping")
    except KeyboardInterrupt:
        print("\n\n✓ Program terminated by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")


if __name__ == "__main__":
    main()
