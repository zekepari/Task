# ICT320 Task 2 – Implementation Task Sheet (Python + Redis Only)

## Phase 1: Setup

- [ ] Install Redis locally (or via Docker).
  - Verify: `redis-cli ping` → should return `PONG`.
- [ ] Install Python dependencies:
  ```bash
  pip install redis pandas
  ```

⸻

Phase 2: Database Design
• Schema (Redis Hash for each user)
• Key format: user:<login_name>
• Fields:
• login
• password
• firstname
• security_q
• security_a
• Security Questions (Redis List)
• Key: security_questions
• Example values:
• “What is your first pet’s name?”
• “What is your mother’s maiden name?”
• “What city were you born in?”

⸻

Phase 3: Python Program
• Build a menu loop with options: 1. Create account 2. Login 3. Forgot password 4. Exit
• Account Creation
• Prompt for login, password, firstname.
• Randomly pick a security question from Redis.
• Ask for answer.
• Save into Redis hash.
• Login
• Prompt login name + password.
• Check Redis hash.
• Return success/failure.
• Forgot Password
• Ask for login name.
• Fetch stored security question + validate answer.
• If correct → update password.
• Else → error message.
• Exit Option
• Break loop cleanly.

⸻

Phase 4: Testing
• CSV Loader
• Write function to load ICT320 - Task 2 - Initial Database-1.csv into Redis.
• Test Cases
• Account creation (success + duplicate).
• Login (success + failure).
• Forgot password (success + failure).

⸻

Phase 5: Advanced Features (Optional)
• Encrypt password before storing (e.g., hashlib.sha256 or bcrypt).
• Create a login log (successful + unsuccessful attempts).
• Append to Redis list login_log.
• Optional: Add Tkinter GUI (while keeping text version).

---
