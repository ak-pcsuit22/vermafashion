# Verma Fashions — Simple Store

This is a small Flask-based web app for a cosmetics & artificial jewellery store. It supports user registration/login, placing orders, viewing order status, and an admin dashboard to update statuses and message buyers.

Quick start (PowerShell on Windows):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = 'app.py'
python app.py
```

Default DB: `app.db` (SQLite) created automatically on first run.

Notes:
- Change `SECRET_KEY` in `app.py` before deploying.
- To make a user an admin, set `is_admin=True` in the database for that user.
