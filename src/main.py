from typing import cast

import uvicorn as uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.api.services.crisp.api import crisp_custom_pattern_search, crisp, crisp_parameters, crisp_debug, \
    crisp_import_marked_findings


session = Session()
CM = ConfigManager()
CM.start_config()

app = FastAPI(openapi_url="/openapi.json", docs_url="/docs")


# Services
app.include_router(crisp, tags=['Crisp'])
app.include_router(crisp_custom_pattern_search, tags=['Crisp'])
if session.has_db:
    app.include_router(crisp_import_marked_findings, tags=['Crisp'])

app.include_router(crisp_parameters, tags=['Parameters'])
if session.has_db:
    app.include_router(crisp_debug, tags=['Parameters'])

if session.has_db:
    from src.api.domains.api import project, run
    from src.api.services.crisp_db.api import crisp_db_actions_project, crisp_db_actions_general
    app.include_router(crisp_db_actions_project, tags=['Database actions'])
    app.include_router(crisp_db_actions_general, tags=['Database actions'])

    # Domains
    app.include_router(project, tags=['CRUD'])
    app.include_router(run, tags=['CRUD'])

app.add_middleware(
    cast('_MiddlewareClass', CORSMiddleware),
    allow_origins=['http://localhost:8086'],
    allow_credentials=True,
    allow_headers=["*"])

if __name__ == '__main__':
    uvicorn.run("main:app", port=8086, host="0.0.0.0", reload=False)
