from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import engine
from app.routes import agent, api, auth, realtime, ui
from app.time_format import format_moscow_time


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        docs_url="/api/docs" if settings.environment != "production" else None,
        redoc_url=None,
    )
    application.state.templates = Jinja2Templates(directory="app/templates")
    application.state.templates.env.filters["moscow_time"] = format_moscow_time
    application.mount("/static", StaticFiles(directory="app/static"), name="static")
    application.include_router(auth.router)
    application.include_router(api.router)
    application.include_router(agent.router)
    application.include_router(realtime.router)
    application.include_router(ui.router)

    @application.get("/health/live", tags=["health"])
    def liveness():
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def readiness():
        try:
            with Session(engine) as db:
                db.execute(text("SELECT 1"))
            return {"status": "ready", "database": "ok"}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "database": "unavailable"},
            )

    @application.exception_handler(403)
    async def forbidden(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse(status_code=403, content={"detail": getattr(exc, "detail", "Недостаточно прав")})
        return application.state.templates.TemplateResponse(
            request=request,
            name="error.html",
            context={"status_code": 403, "message": "Недостаточно прав для этого действия."},
            status_code=403,
        )

    return application


app = create_app()
