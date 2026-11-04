#!/usr/bin/env python3
"""Embed the OS installer without adding distro policy to the C client."""
import json,sys
from pathlib import Path
installer,controller,output=map(Path,sys.argv[1:])
output.write_text('static const char linux_install_script[] = '+json.dumps(installer.read_text(),ensure_ascii=False)+';\n'
                  'static const char linux_service_script[] = '+json.dumps(controller.read_text(),ensure_ascii=False)+';\n',encoding='utf-8')
