# ---------------------------------------------------------------------------------------------------------------------
# TimeManager.py
#
# Author      : Peter Heijligers
# Description : Time of execution
#
#
# Date       Ini Description
# ---------- --- ------------------------------------------------------------------------------------------------------
# 2020-01-31 PHe First creation
# ---------------------------------------------------------------------------------------------------------------------

import time

from src.gl.Const import EMPTY

time_exec_max_s = 60 * 60  # 1 hour
time_exec_threshold_ms = 0
time_exec_error = False


def time_exec(method):
    def calculate_duration(*args, **kwargs):
        global time_exec_error
        ts = time.time()
        result = method(*args, **kwargs)
        te = time.time()

        duration_s = (te - ts)
        duration_ms = duration_s * 1000

        if time_exec_threshold_ms > 0:
            if duration_ms > time_exec_threshold_ms:
                time_text = f": {kwargs['time_text']} " if 'time_text' in kwargs else EMPTY
                print(f'{method.__name__}{time_text}{duration_ms:2.2f} ms')

        if 0 < time_exec_max_s < duration_s:
            print(f'Duration higher than maximum duration (s) ({time_exec_max_s})')
            time_exec_error = True

        return result

    return calculate_duration
