# ICT320 Task 2 – User Authentication (Redis)

## Run

1. Start Redis (e.g. `redis-server`) and ensure `redis-cli ping` returns `PONG`.
2. `pip install -r requirements.txt`
3. `python user_auth_system.py`

Use the menu to:

- Create Account
- Login
- Forgot Password
- Load CSV Data (loads `ICT320 - Task 2 - Initial Database-1.csv`)
- Show Statistics
- Run Tests

## Optional Environment Variables

```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_DB=0
```
