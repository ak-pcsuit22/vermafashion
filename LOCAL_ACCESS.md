Accessing the site from other devices on the same local network

This project runs a Flask development server. By default it binds to `0.0.0.0` (all interfaces) when started using the instructions below, so other devices on the same LAN can open it.

Quick run (PowerShell)

```powershell
# from the project root
$env:FLASK_APP='app.py'; $env:FLASK_DEBUG='1'; python -m flask run --host=0.0.0.0 --port=5000
```

Or use the convenience environment variables added to `app.py`:

```powershell
# respected by the app's __main__ block
$env:FLASK_RUN_HOST='0.0.0.0'; $env:PORT='5000'; python app.py
```

After starting, the app will print a local URL in the terminal, for example:

  * Starting Flask on 0.0.0.0:5000 (open from other devices at http://192.168.1.12:5000/)

Open that printed `http://<your-lan-ip>:5000/` address in a browser on another device connected to the same Wi‑Fi / network.

Notes & troubleshooting

- Windows Firewall: If you cannot reach the site from another device, allow Python (or the port) through the Windows Firewall: Search "Windows Defender Firewall" → "Allow an app or feature" → allow `python.exe` for Private networks, or add a rule to open TCP port `5000` on Private networks.

- Find your machine's IP manually: run `ipconfig` in PowerShell and look for the IPv4 address on your active network adapter (often `192.168.x.x` or `10.x.x.x`).

- Use HTTPS in production, and use a production WSGI server (Gunicorn / Waitress) behind a proper web server for security and performance. The Flask dev server is fine for local testing only.

- If you want to use a different port, set `$env:PORT='8080'` (or pass `--port` to `flask run`).

If you want, I can also:
- Add a small script (PowerShell) `run-local.ps1` to start the server and print the URL.
- Add instructions for macOS / Linux shells.

Security notes

- Use a strong `SECRET_KEY` in production and store it in environment variables. See `.env.example` for recommended variables.
- Consider installing `flask-talisman` and `Flask-WTF` to enable security headers and CSRF protection in production:

```powershell
pip install flask-talisman Flask-WTF
```

- Don’t commit your `.env` file (containing secrets) to version control.
- On Windows, ensure `app.db` is not accessible from the web server and is stored outside public directories if possible.

- SMTP / Email configuration

The OTP and password reset features send emails using SMTP. Provide the following environment variables to enable real email sending:

```
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_USE_TLS=1
ADMIN_EMAIL=fashion.vistashop@gmail.com
```

If SMTP is not configured, the app prints OTP codes to the server console (development fallback).
