"""Public plugin API.

Plugin authors subclass :class:`VtkPlugin` and either drop the file into a
``--plugin-dir`` directory or ship it as a package exposing a
``vtknet.plugins`` entry point. See ``examples/plugins/hello_ports.py``.
"""

from vtknet.core.plugins import (
    ENTRY_POINT_GROUP,
    VtkPlugin,
    discover,
    load_file_plugins,
)

__all__ = ["ENTRY_POINT_GROUP", "VtkPlugin", "discover", "load_file_plugins"]
