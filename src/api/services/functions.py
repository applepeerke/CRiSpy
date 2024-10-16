import os.path
from os import listdir

from src.gl.BusinessLayer.LogManager import Singleton as Log
from src.gl.BusinessLayer.SessionManager import Singleton as Session
from src.gl.Const import BASE_OUTPUT_SUBDIR, RESULTS_DIR

log = Log()
session = Session()
session.set_paths()


def run(db_action, crisp_db, check_only=False):
    crisp_db.start(action_name=db_action, check_only=check_only)
    return {"lines": log.get_log()}


def get_txt_as_lines(path) -> list:
    if not path or not os.path.isfile(path):
        return []
    with open(path, 'r') as file:
        lines = file.readlines()
    return [line.rstrip('\r\n') for line in lines]


def get_latest_result_folder(input_dir) -> str | None:
    """ Get the most recent folder in Output/Result where 'input_path' is listed in Log.txt. """
    # Get 'crisp_result...' folders, recent first
    dir_names = sorted(
        [d for d in listdir(os.path.join(session.output_dir, RESULTS_DIR)) if d.startswith(BASE_OUTPUT_SUBDIR)],
        reverse=True)
    for result_dir in dir_names:
        result_dir_abs = os.path.join(session.output_dir, RESULTS_DIR, result_dir)
        # Result folder contains CRiSp results of input dir.
        # Check if this crisp_result folder corresponds with input_dir by reading the log.
        path = os.path.join(result_dir_abs, 'Log.txt')
        if not os.path.isfile(path):
            continue

        # Read Log.txt
        with open(path, 'r') as f:
            lines = f.readlines()
        count = sum(1 for _ in range(20) for line in lines if input_dir in line)
        if count > 0:
            return result_dir_abs
    return None


def get_filename_from_prefix(dir_name, prefix, subdir=None) -> str | None:
    """ Get unique filename in a (sub)dir that startswith a prefix """
    dir_name = os.path.join(dir_name, subdir) if subdir else dir_name
    if not os.path.isdir(dir_name) or not prefix:
        return None
    file_names = [f for f in listdir(dir_name) if f.startswith(prefix)]
    return file_names[0] if len(file_names) == 1 else None
