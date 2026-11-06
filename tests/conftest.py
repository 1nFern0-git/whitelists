"""Общая загрузка инструментов: имена файлов с дефисом импортируются по пути."""
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

TOOLS = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load(name: str, filename: str) -> ModuleType:
    """Модуль по имени файла: check-domains.py обычным import не взять."""
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
