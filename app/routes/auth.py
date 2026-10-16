from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import get_settings
from app.database import get_db
from app.models import User
from app.security import (
    COOKIE_NAME,
    LOGIN_CSRF_COOKIE,
    AuthContext,
    create_session,
    get_ui_auth_context,
    make_login_csrf,
    verify_csrf,
    verify_login_csrf,
    verify_password,
)

router = APIRouter(tags=["authentication"])


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else None


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    token = make_login_csrf()
    response = request.app.state.templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"csrf_token": token, "error": None},
    )
    response.set_cookie(
        LOGIN_CSRF_COOKIE,
        token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="strict",
        max_age=600,
    )
    return response


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not verify_login_csrf(csrf_token, request.cookies.get(LOGIN_CSRF_COOKIE)):
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf_token": make_login_csrf(), "error": "Форма устарела. Обновите страницу."},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    user = db.scalar(select(User).where(User.username == username.strip()))
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        write_audit(
            db,
            actor=user,
            action="auth.login_failed",
            entity_type="user",
            entity_id=user.id if user else None,
            source_ip=client_ip(request),
        )
        db.commit()
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf_token": csrf_token, "error": "Неверное имя пользователя или пароль."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    session, raw_token = create_session(db, user)
    write_audit(
        db,
        actor=user,
        action="auth.login",
        entity_type="user_session",
        entity_id=session.id,
        source_ip=client_ip(request),
    )
    db.commit()
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        COOKIE_NAME,
        raw_token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="strict",
        max_age=get_settings().session_hours * 3600,
    )
    response.delete_cookie(LOGIN_CSRF_COOKIE)
    return response


@router.post("/logout")
def logout(
    request: Request,
    csrf_token: str = Form(...),
    context: AuthContext = Depends(get_ui_auth_context),
    db: Session = Depends(get_db),
):
    verify_csrf(context, csrf_token)
    write_audit(
        db,
        actor=context.user,
        action="auth.logout",
        entity_type="user_session",
        entity_id=context.session.id,
        source_ip=client_ip(request),
    )
    db.delete(context.session)
    db.commit()
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response
