import os
import tempfile

# Variables d'environnement de test — DOIVENT être posées avant l'import de `main`,
# car main.py lit os.getenv(...) au chargement du module.
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["APP_PASSWORD"] = ""
os.environ["PREMIUM_ENABLED"] = "false"
os.environ["GROQ_API_KEY"] = ""
os.environ["DB_PATH"] = _db_path
