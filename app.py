"""
Broken Authentication Flow CTF — "VaultLogin" (easy)
----------------------------------------------------
A login flow with a two-step authentication:

    1. POST /login   -> verify username + password, start a session
    2. /verify       -> enter the 6-digit OTP "emailed" to the user
    3. /account      -> protected page holding the flag

The vulnerability: /account only checks WHO you are (`pre_auth_user` is set
the moment your password is accepted) and never checks WHETHER you completed
the MFA step (`mfa_passed`). Because the OTP is generated server-side and
never shown to the player, the *intended* MFA path is impossible to finish —
so the only way to reach the flag is to browse straight to /account after
logging in, skipping the OTP step entirely.

Lesson: authentication state must be enforced on every protected resource.
A session that says "this is alice" is not the same as "alice finished
logging in."

Teaching target — do not reuse this pattern in real code.
"""

import os
import secrets

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    session,
)

FLAG = os.environ.get("FLAG", "CTF{mfa_means_nothing_if_you_dont_enforce_it}")
DEMO_USER = os.environ.get("DEMO_USER", "alice")
DEMO_PASS = os.environ.get("DEMO_PASS", "password123")

app = Flask(__name__)
# Sessions are signed with this; random per-boot unless you pin SECRET_KEY.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


@app.route("/")
def index():
    return render_template("login.html", demo_user=DEMO_USER, demo_pass=DEMO_PASS)


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if username == DEMO_USER and password == DEMO_PASS:
        session.clear()
        # Password accepted -> we remember who this is...
        session["pre_auth_user"] = username
        # ...and generate an OTP that is "emailed" to them (never shown here).
        session["otp"] = f"{secrets.randbelow(1000000):06d}"
        # ...but the login is NOT complete until MFA passes.
        session["mfa_passed"] = False
        return redirect(url_for("verify"))
    return render_template(
        "login.html",
        demo_user=DEMO_USER,
        demo_pass=DEMO_PASS,
        error="Invalid username or password.",
    )


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if not session.get("pre_auth_user"):
        return redirect(url_for("index"))
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        if code and code == session.get("otp"):
            session["mfa_passed"] = True
            return redirect(url_for("account"))
        return render_template("verify.html", error="Incorrect code. Try again.")
    return render_template("verify.html")


@app.route("/account")
def account():
    # VULNERABLE ON PURPOSE:
    # This only checks identity (pre_auth_user), not whether MFA completed.
    # The correct check would be: if not session.get("mfa_passed"): abort/redirect.
    if not session.get("pre_auth_user"):
        return redirect(url_for("index"))
    return render_template(
        "account.html",
        user=session["pre_auth_user"],
        flag=FLAG,
        mfa=session.get("mfa_passed", False),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
