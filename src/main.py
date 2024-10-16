from typing import cast

import uvicorn as uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse

from src.api.services.crisp.api import crisp_custom_pattern_search, crisp, crisp_parameters, crisp_findings, \
    crisp_endpoints, crisp_input_validation, crisp_log
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session

session = Session()
CM = ConfigManager()
CM.start_config()

app = FastAPI(openapi_url="/openapi.json", docs_url="/docs")


# Services
app.include_router(crisp, tags=['CRiSpy'])
app.include_router(crisp_custom_pattern_search, tags=['CRiSpy'])
app.include_router(crisp_findings, tags=['CRiSpy'], default_response_class=HTMLResponse)
app.include_router(crisp_endpoints, tags=['CRiSpy'], default_response_class=HTMLResponse)
app.include_router(crisp_input_validation, tags=['CRiSpy'], default_response_class=HTMLResponse)
app.include_router(crisp_log, tags=['CRiSpy'], default_response_class=HTMLResponse)

app.include_router(crisp_parameters, tags=['Parameters'])


app.add_middleware(
    cast('_MiddlewareClass', CORSMiddleware),
    allow_origins=['http://localhost:8086'],
    allow_credentials=True,
    allow_headers=["*"])

if __name__ == '__main__':
    uvicorn.run("main:app", port=8086, host="0.0.0.0", reload=False)
