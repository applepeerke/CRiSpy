from typing import cast

import uvicorn as uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.api.services.crisp.api import crispy_custom_pattern_search, crispy, crispy_parameters
from src.gl.BusinessLayer.ConfigManager import ConfigManager
from src.gl.BusinessLayer.SessionManager import Singleton as Session

session = Session()
CM = ConfigManager()
CM.start_config()

app = FastAPI(openapi_url="/openapi.json", docs_url="/docs")


# Services
app.include_router(crispy, tags=['CRiSpy'])
app.include_router(crispy_custom_pattern_search, tags=['CRiSpy'])

app.include_router(crispy_parameters, tags=['Parameters'])


app.add_middleware(
    cast('_MiddlewareClass', CORSMiddleware),
    allow_origins=['http://localhost:8086'],
    allow_credentials=True,
    allow_headers=["*"])

if __name__ == '__main__':
    uvicorn.run("main:app", port=8086, host="0.0.0.0", reload=False)
