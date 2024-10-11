# ---------------------------------------------------------------------------------------------------------------------
# UserInput.py
#
# Author      : Peter Heijligers
# Description : Validation functions
#
# - normalize_dir = isProjectValid a directory name for different platforms.
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2017-09-07 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------
from src.gl.Const import EMPTY, Y, N


def is_confirmative(question='Continue [y|n]?', interactive=True, default=False):
    """
    Ask the user for continuation.
    """
    if not interactive:
        return default

    continue_yn = EMPTY

    while not (continue_yn == Y or continue_yn == N):
        continue_yn = (ask(question + ' ')).lower()

    if continue_yn == N:
        return False
    else:
        return True


def ask(question):
    """
    Ask the user for input.
    """
    return input(question)
