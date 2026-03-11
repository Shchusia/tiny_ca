from logging import DEBUG, Formatter, StreamHandler, getLogger

DEFAULT_LOGGER = getLogger("rag_llm")
DEFAULT_LOGGER.setLevel(DEBUG)
_console_handler = StreamHandler()
_formatter = Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
_console_handler.setFormatter(_formatter)
DEFAULT_LOGGER.addHandler(_console_handler)
DT_STR_FORMAT = "%Y-%m-%d %H:%M:%S"
