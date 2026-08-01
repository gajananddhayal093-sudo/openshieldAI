"""
OpenShield AI Configuration
"""

import os
from modules.utils.env_loader import load_env

load_env()

APP_NAME = "OpenShield AI"
VERSION = "2.0.0"

DEBUG = True

BOT_TOKEN = os.getenv("BOT_TOKEN", "")

ADMIN_ID = int(os.getenv("ADMIN_ID", "56"))
