from src.gl.BusinessLayer.LogManager import Singleton as Log

log = Log()


def run(db_action, crisp_db, check_only=False):
    crisp_db.start(action_name=db_action, check_only=check_only)
    return {"log": log.get_log()}
