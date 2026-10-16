"""
Plain-Django views for OAuth 2.1 Authorization Code + PKCE (agent login).

Mounted at SITE ROOT (not under /api/): the MCP bridge trims `/api` from
the control-plane base before discovery, so these live at
`/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`.

Flow: GET /oauth/authorize (validate → login form → consent screen) →
POST approve → 302 to loopback `redirect_uri?code=…&state=…` →
POST /oauth/token (PKCE verify) → top-level JSON token bundle.

These are sync function views (Django session + CSRF apply normally).
Token responses carry `Cache-Control: no-store` explicitly.
"""

from __future__ import annotations

import html
import json
import logging
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from apps.common.exceptions import AuthenticationError
from . import oauth as oauth_svc
from .models import User

logger = logging.getLogger("apps.accounts")

CLIENT_DISPLAY_NAMES = {
    "agentsecrets-mcp": "AgentSecrets MCP Bridge",
}


def _issuer_base(request: HttpRequest) -> str:
    override = (getattr(settings, "OAUTH_ISSUER_BASE_URL", "") or "").strip().rstrip("/")
    if override:
        return override
    return request.build_absolute_uri("/") .rstrip("/")


BRAND_CSS = """
:root{--bg:#fff;--ink:#1B1B1B;--muted:#666;--faint:#8a8a93;--card:#F5F5F7;
--teal:#007F6A;--teal-dark:#005E50;--accent:#00C6A5;--line:rgba(0,0,0,.08);
--rose-bg:#fff1f2;--rose-line:#fecdd3;--rose-tx:#9f1239}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif;font-size:15px;-webkit-font-smoothing:antialiased;padding:48px 16px}
.as-card{max-width:440px;margin:0 auto;background:#fff;border:1px solid rgba(0,0,0,.06);border-radius:24px;padding:32px;box-shadow:0 8px 30px rgba(0,0,0,.05)}
.as-brand{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.as-brand svg{flex:none}
.as-brand span{font-weight:650;font-size:17px;letter-spacing:-.02em}
.as-brand em{font-style:normal;color:var(--teal)}
.as-pill{display:inline-block;background:var(--card);border:1px solid rgba(0,0,0,.05);border-radius:999px;padding:3px 12px;font-size:12px;font-weight:600}
.as-title{font-size:22px;font-weight:650;letter-spacing:-.02em;margin:14px 0 8px}
.as-sub{color:var(--muted);font-size:14px;line-height:1.55;margin-bottom:18px}
.as-sub b{color:var(--ink)}
.as-field{margin-bottom:12px}
.as-field label{display:block;font-size:12.5px;font-weight:600;margin-bottom:6px}
.as-field input{width:100%;padding:11px 14px;font-size:14px;border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--ink);outline:none}
.as-field input:focus{border-color:var(--teal);background:#fff}
.as-btn{display:block;width:100%;padding:12px;border:none;border-radius:12px;background:var(--teal-dark);color:#fff;font-size:14.5px;font-weight:650;cursor:pointer;margin-top:6px}
.as-btn:hover{background:var(--teal)}
.as-row{display:flex;gap:10px;margin-top:6px}
.as-row .as-btn{margin-top:0}
.as-btn-ghost{display:block;width:100%;padding:12px;border:1px solid var(--line);border-radius:12px;background:#fff;color:var(--ink);font-size:14.5px;font-weight:600;cursor:pointer}
.as-btn-ghost:hover{background:var(--card)}
.as-alert{background:var(--rose-bg);border:1px solid var(--rose-line);color:var(--rose-tx);border-radius:12px;padding:10px 14px;font-size:13px;margin-bottom:14px}
.as-code{font-family:"Space Mono",ui-monospace,Menlo,monospace;font-size:12.5px;background:var(--card);border-radius:8px;padding:2px 8px}
.as-list{list-style:none;padding:0;margin:0 0 18px}
.as-list li{position:relative;padding:7px 0 7px 26px;font-size:13.5px;color:var(--muted);line-height:1.5}
.as-list li b{color:var(--ink)}
.as-list li::before{content:"";position:absolute;left:2px;top:13px;width:14px;height:14px;border-radius:50%;background:var(--accent) url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="4"><path d="M20 6L9 17l-5-5"/></svg>') center/9px no-repeat}
.as-list li.no::before{background:#c9c9d1}
.as-foot{margin-top:22px;text-align:center;font-size:11.5px;color:var(--faint)}
"""


def _brandmark() -> str:
    return (
        "<svg width='26' height='26' viewBox='0 0 24 24' fill='none'>"
        "<path d='M12 2l8 3.5v5.2c0 5-3.4 9.4-8 11.3-4.6-1.9-8-6.3-8-11.3V5.5L12 2z' "
        "fill='#007F6A'/>"
        "<circle cx='12' cy='10.5' r='2.6' fill='none' stroke='white' stroke-width='1.8'/>"
        "<path d='M12 13.1v3.4' stroke='white' stroke-width='1.8' stroke-linecap='round'/>"
        "</svg>"
    )


def _shell(*, title: str, badge: str, inner: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)} — AgentSecrets</title>"
        f"<style>{BRAND_CSS}</style></head><body><main class='as-card'>"
        f"<div class='as-brand'>{_brandmark()}<span>Agent<em>Secrets</em></span></div>"
        f"<span class='as-pill'>{html.escape(badge)}</span>{inner}"
        "<p class='as-foot'>Secured by AgentSecrets · zero-knowledge credential infrastructure</p>"
        "</main></body></html>"
    )


def _error_page(message: str, status: int = 400) -> HttpResponse:
    return HttpResponse(
        _shell(
            title="Authorization error",
            badge="Agent login",
            inner="<h1 class='as-title'>Cannot start login</h1>"
            f"<div class='as-alert'>{html.escape(message)}</div>"
            "<p class='as-sub'>Close this tab and return to your agent.</p>",
        ),
        status=status,
        content_type="text/html",
    )


def _read_params(request: HttpRequest) -> dict[str, str]:
    src = request.POST if request.method == "POST" else request.GET
    return {
        "response_type": (src.get("response_type") or "").strip(),
        "client_id": (src.get("client_id") or "").strip(),
        "redirect_uri": (src.get("redirect_uri") or "").strip(),
        "scope": (src.get("scope") or "").strip(),
        "state": (src.get("state") or "").strip(),
        "code_challenge": (src.get("code_challenge") or "").strip(),
        "code_challenge_method": (src.get("code_challenge_method") or "S256").strip(),
    }


def _validate_authorize_params(params: dict[str, str]) -> str | None:
    """Return an error message, or None when the request is well-formed."""
    if params["response_type"] != "code":
        return "Unsupported response_type (only 'code' is supported)."
    if params["client_id"] not in oauth_svc.OAUTH_PUBLIC_CLIENTS:
        return "Unknown client_id."
    if not oauth_svc.is_loopback_callback(params["redirect_uri"]):
        return (
            "Invalid redirect_uri. Only loopback callbacks "
            "(http://127.0.0.1[:port]/callback or http://localhost[:port]/callback) "
            "are accepted for this client."
        )
    if not params["code_challenge"]:
        return "Missing code_challenge (PKCE S256 is required)."
    if params["code_challenge_method"] != "S256":
        return "Only code_challenge_method=S256 is supported."
    if len(params["code_challenge"]) > 128:
        return "Malformed code_challenge."
    return None


def _redirect_with(params: dict[str, str], extra: dict[str, str]):
    sep = "&" if "?" in params["redirect_uri"] else "?"
    query = dict(extra)
    if params["state"]:
        query["state"] = params["state"]
    return redirect(params["redirect_uri"] + sep + urlencode(query))


def _login_form(request: HttpRequest, params: dict[str, str], error: str | None = None) -> HttpResponse:
    def hidden(name: str) -> str:
        return (
            f"<input type='hidden' name='{name}' "
            f"value='{html.escape(params[name], quote=True)}'>"
        )

    err = (
        f"<div class='as-alert'>{html.escape(error)}</div>" if error else ""
    )
    inner = (
        "<h1 class='as-title'>Sign in</h1>"
        "<p class='as-sub'>An AI agent (<b>AgentSecrets MCP Bridge</b>) is asking "
        "for access to your account. Sign in to review the request.</p>"
        f"{err}"
        "<form method='post'>"
        f"<input type='hidden' name='csrfmiddlewaretoken' value='{get_token(request)}'>"
        "<input type='hidden' name='action' value='login'>"
        + hidden("response_type")
        + hidden("client_id")
        + hidden("redirect_uri")
        + hidden("scope")
        + hidden("state")
        + hidden("code_challenge")
        + hidden("code_challenge_method")
        + "<div class='as-field'><label for='as-email'>Email</label>"
        "<input id='as-email' type='email' name='email' required autocomplete='email'></div>"
        "<div class='as-field'><label for='as-pass'>Password</label>"
        "<input id='as-pass' type='password' name='password' required "
        "autocomplete='current-password'></div>"
        "<button class='as-btn' type='submit'>Sign in</button>"
        "</form>"
    )
    return HttpResponse(
        _shell(title="Sign in", badge="Agent login", inner=inner),
        content_type="text/html",
    )


def _consent_form(request: HttpRequest, params: dict[str, str], user: User) -> HttpResponse:
    def hidden(name: str) -> str:
        return (
            f"<input type='hidden' name='{name}' "
            f"value='{html.escape(params[name], quote=True)}'>"
        )

    client = CLIENT_DISPLAY_NAMES.get(params["client_id"], params["client_id"])
    scope = oauth_svc.normalize_scope(params["scope"]) or "read write"
    inner = (
        f"<h1 class='as-title'>Allow <b>{html.escape(client)}</b>?</h1>"
        f"<p class='as-sub'>Signed in as <b>{html.escape(user.email)}</b> · "
        f"scope <span class='as-code'>{html.escape(scope)}</span></p>"
        "<ul class='as-list'>"
        "<li><b>List projects</b> and read secret <b>key names</b></li>"
        "<li><b>Call your APIs</b> with stored secrets injected outside its reach</li>"
        "<li><b>Never sees secret values</b> — names only, enforced at the tool boundary</li>"
        "<li class='no'><b>Revoke anytime</b> — access ends the moment you say so</li>"
        "</ul>"
        "<div class='as-row'>"
        "<form method='post' style='flex:1'>"
        f"<input type='hidden' name='csrfmiddlewaretoken' value='{get_token(request)}'>"
        "<input type='hidden' name='action' value='approve'>"
        + hidden("response_type")
        + hidden("client_id")
        + hidden("redirect_uri")
        + hidden("scope")
        + hidden("state")
        + hidden("code_challenge")
        + hidden("code_challenge_method")
        + "<button class='as-btn' type='submit'>Allow</button>"
        "</form>"
        "<form method='post' style='flex:1'>"
        f"<input type='hidden' name='csrfmiddlewaretoken' value='{get_token(request)}'>"
        "<input type='hidden' name='action' value='deny'>"
        + hidden("response_type")
        + hidden("client_id")
        + hidden("redirect_uri")
        + hidden("scope")
        + hidden("state")
        + hidden("code_challenge")
        + hidden("code_challenge_method")
        + "<button class='as-btn-ghost' type='submit'>Deny</button>"
        "</form>"
        "</div>"
    )
    return HttpResponse(
        _shell(title="Authorize agent", badge="Agent login", inner=inner),
        content_type="text/html",
    )


@require_GET
def oauth_discovery(request: HttpRequest) -> JsonResponse:
    return JsonResponse(oauth_svc.build_discovery(base_url=_issuer_base(request)))


def oauth_authorize(request: HttpRequest) -> HttpResponse:
    params = _read_params(request)

    problem = _validate_authorize_params(params)
    if problem:
        # redirect_uri itself is untrusted here: render, never redirect.
        return _error_page(problem, status=400)

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "login":
            email = (request.POST.get("email") or "").strip()
            password = request.POST.get("password") or ""
            user = authenticate(request, email=email, password=password)
            if user is None or not user.is_active:
                return _login_form(request, params, error="Invalid email or password.")
            login(request, user)
            return _consent_form(request, params, user)
        if action == "approve":
            if not request.user.is_authenticated or not isinstance(request.user, User):
                return _login_form(request, params, error="Session expired — sign in again.")
            if not request.user.is_active:
                return _error_page("Account is disabled.", status=403)
            code = oauth_svc.issue_code(
                user=request.user,
                client_id=params["client_id"],
                redirect_uri=params["redirect_uri"],
                scope=oauth_svc.normalize_scope(params["scope"]),
                code_challenge=params["code_challenge"],
                code_challenge_method=params["code_challenge_method"],
            )
            return _redirect_with(params, {"code": code})
        if action == "deny":
            return _redirect_with(params, {"error": "access_denied"})
        return _error_page("Unknown action.", status=400)

    # GET: login first, consent when already signed in.
    if request.user.is_authenticated and isinstance(request.user, User):
        return _consent_form(request, params, request.user)
    return _login_form(request, params)


@csrf_exempt
@require_POST
def oauth_token(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        content_type = request.content_type or ""
        if content_type.startswith("application/x-www-form-urlencoded"):
            payload = dict(request.POST)
        else:
            return JsonResponse({"error": "invalid_request"}, status=400)

    grant_type = (payload.get("grant_type") or "").strip()
    client_id = (payload.get("client_id") or "").strip()

    if grant_type == "authorization_code":
        if client_id not in oauth_svc.OAUTH_PUBLIC_CLIENTS:
            return _token_error("invalid_client")
        try:
            user, scope = oauth_svc.redeem_code(
                raw_code=(payload.get("code") or "").strip(),
                client_id=client_id,
                redirect_uri=(payload.get("redirect_uri") or "").strip(),
                code_verifier=(payload.get("code_verifier") or "").strip(),
            )
            bundle = oauth_svc.mint_token_bundle(user=user)
        except AuthenticationError:
            return _token_error("invalid_grant")
        bundle["scope"] = scope
        return _token_json(bundle)

    if grant_type == "refresh_token":
        try:
            bundle = oauth_svc.rotate_refresh(
                refresh_token_str=(payload.get("refresh_token") or "").strip()
            )
        except AuthenticationError:
            return _token_error("invalid_grant")
        return _token_json(bundle)

    return _token_error("unsupported_grant_type")


def _token_error(code: str, status: int = 401) -> JsonResponse:
    resp = JsonResponse({"error": code}, status=status)
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


def _token_json(bundle: dict) -> JsonResponse:
    resp = JsonResponse(bundle)
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp
