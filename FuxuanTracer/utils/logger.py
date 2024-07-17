
from FuxuanTracer.dependecy.needModules import (
    loguru, sys
)

BOLD = "\033[1m"
RESET = "\033[0m"

# 移除默认处理器
logger = loguru.logger
logger.remove()

# 添加自定义处理器
logger.add(
    sys.stdout,
    format=(
        f"<green>{BOLD}{{time:YYYY-MM-DD HH:mm:ss}} | </green>{RESET}"
        f"<level>{BOLD}{{level: <8}} </level> | {RESET}"
        f"<cyan>{BOLD}{{process.name}}</cyan>{RESET}."
        f"<cyan>{BOLD}{{thread.name}} | </cyan>{RESET}"
        f"<magenta>{BOLD}{{name}}</magenta>{RESET}."
        f"<magenta>{BOLD}{{function}} | </magenta>{RESET}"
        f"<blue>{BOLD}{{file}}</blue>{RESET}:<blue>{BOLD}{{line}} | </blue>{RESET}"
        f"<level>{BOLD}{{message}}</level>{RESET}"
    ),
    colorize=True,
    enqueue=True,
    backtrace=True
)