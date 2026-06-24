"""Config de pytest del add-on.

El add-on corre con `WORKDIR /app` y `COPY zkteco_adms/ /app/` (ver Dockerfile),
asi que los imports del codigo son planos (`import server`, `from audit import
...`). Para que los tests resuelvan esos imports, agregamos el directorio del
paquete `zkteco_adms/` al sys.path.
"""

import os
import sys

_PKG_DIR = os.path.join(os.path.dirname(__file__), "..", "zkteco_adms")
sys.path.insert(0, os.path.abspath(_PKG_DIR))
