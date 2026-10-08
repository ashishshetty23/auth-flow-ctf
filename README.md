# Broken Authentication Flow CTF — "VaultLogin" (easy)

A login flow that **enforces the wrong thing**. You can log in with the demo
password, but the app then demands a one-time code it "emails" you — a code
you can never read. The flag sits on the account page. Can you get in anyway?

## The flow

1. `POST /login` — checks username + password, starts your session.
2. `/verify` — asks for the 6-digit OTP "emailed" to you.
3. `/account` — protected page holding the flag.

## The bug

When your password is accepted, the session immediately records **who** you
are (`pre_auth_user`), but marks `mfa_passed = False`. The `/account` page
only checks that `pre_auth_user` is set — it never checks `mfa_passed`. So the
MFA step is cosmetic: nothing enforces it on the protected resource.

Because the OTP is generated server-side and never shown, you *can't* complete
MFA the intended way — which is the whole point. You have to skip it.

## Intended solution

1. Open the site, log in with `alice` / `password123`.
2. You land on the **two-step verification** page. Ignore it.
3. Manually browse to **`/account`** (just change the URL).
4. The flag is there, with a banner confirming you bypassed MFA.

```bash
# Same thing from the command line:
curl -s -c jar http://localhost:5000/ > /dev/null
curl -s -c jar -b jar -d 'username=alice&password=password123' http://localhost:5000/login
curl -s -b jar http://localhost:5000/account   # flag is in the HTML
```

## Run locally

```bash
cd auth-flow-ctf
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

## Deploy on Render

This is a plain Python web service (no Docker needed):

1. Push this folder to a GitHub repo.
2. Render → **New → Web Service** → connect the repo.
   - Render reads `render.yaml` automatically (Blueprint). Confirm:
     Runtime **Python**, Build `pip install -r requirements.txt`,
     Start `gunicorn app:app --bind 0.0.0.0:$PORT`.
3. Set the **`FLAG`** env var to your real flag.
4. Deploy and share the `https://<name>.onrender.com` URL.

### Config

| Var          | Default                                      | Purpose                     |
|--------------|----------------------------------------------|-----------------------------|
| `FLAG`       | `CTF{mfa_means_nothing_if_you_dont_enforce_it}` | Flag shown on `/account`. |
| `DEMO_USER`  | `alice`                                       | Demo login username.        |
| `DEMO_PASS`  | `password123`                                 | Demo login password.        |
| `SECRET_KEY` | random per boot                               | Flask session signing key.  |

## The fix (for the writeup)

Guard every protected route on the *completed* auth state, not identity:

```python
@app.route("/account")
def account():
    if not session.get("mfa_passed"):      # <-- enforce MFA here
        return redirect(url_for("verify"))
    ...
```

Better still, don't store a user identity in the session until the full flow
finishes — keep MFA state server-side and treat the session as unauthenticated
until every step passes.

> ⚠️ Intentionally insecure demo. Don't reuse this auth pattern.
