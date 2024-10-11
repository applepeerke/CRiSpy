from fastapi import HTTPException
from starlette import status

from src.gl.Functions import remove_color_code


class GeneralException(HTTPException):

    def __init__(self, message):
        self.message = remove_color_code(message)
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=self.message)
