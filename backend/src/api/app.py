"""
FastAPI 应用实例、路由聚合。
"""
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.api.middleware.request_id import RequestIDMiddleware
from src.api.routes import agents, auth, case_skills, cases, evidence, pipelines, projects, reports, sessions, skills
from src.core.exceptions import NeoException, http_exception_handler, neo_exception_handler


def create_app(
    lifespan: asynccontextmanager[AsyncIterator[None]] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Neo API",
        description="数字取证与事件响应多智能体 Agent 平台",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_exception_handler(NeoException, neo_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)

    # 路由挂载（前缀 /api/v1）
    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(projects.router, prefix=api_prefix)
    app.include_router(cases.router, prefix=api_prefix)
    app.include_router(sessions.router, prefix=api_prefix)
    app.include_router(evidence.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(pipelines.router, prefix=api_prefix)
    app.include_router(agents.router, prefix=api_prefix)
    app.include_router(skills.router, prefix=api_prefix)
    app.include_router(case_skills.router, prefix=api_prefix)

    @app.get("/health")
    def health():
        """健康检查（白名单，无需鉴权）。"""
        return {"status": "ok"}

    return app
