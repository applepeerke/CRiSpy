import os
from typing import Optional

from src.gl.Const import EMPTY
from src.gl.Functions import path_leaf
from src.gl.Validate import normalize_dir


def get_k8s_dir(input_dir) -> Optional[str]:
    if not input_dir:
        return None
    # Find k8s folder
    data_dir = normalize_dir(f'{input_dir}k8s')
    # - Not found: try level left to "../src" too.
    if not os.path.isdir(data_dir):
        data_dir, _ = path_leaf(input_dir)
        data_dir = normalize_dir(data_dir)
        data_dir = normalize_dir(f'{data_dir}k8s')
        if os.path.isdir(data_dir):
            return data_dir
    return None


def sanitize(value) -> str:
    return value.strip().rstrip(';').replace('"', EMPTY)
