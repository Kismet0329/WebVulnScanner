# plugin_loader.py
import importlib
import pkgutil
import plugins
from plugins.base import ScannerPlugin

def load_plugins(only=None, exclude=None):
    """
    加载所有插件
    :param only: 只加载指定名称的插件列表
    :param exclude: 排除指定名称的插件列表
    """
    plugin_classes = []
    for _, modname, _ in pkgutil.iter_modules(plugins.__path__):
        module = importlib.import_module(f"plugins.{modname}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, ScannerPlugin) and attr is not ScannerPlugin:
                if only and attr.name not in only:
                    continue
                if exclude and attr.name in exclude:
                    continue
                plugin_classes.append(attr)
    return plugin_classes