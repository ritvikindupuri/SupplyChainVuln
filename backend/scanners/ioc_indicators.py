"""
Curated IOC (Indicator of Compromise) lists for SecureChain.
============================================================
These are vetted, built-in indicators checked against commit diffs. They are
deterministic and require no external calls or tokens.

NOTE ON SCOPE (honest framing):
SecureChain matches *known* indicators here. It does NOT claim to detect
"zero-days" (previously-unknown vulnerabilities). The novel-risk capability of
this tool is the AI consensus reasoning about newly-introduced suspicious code
in a commit -- which is distinct from, and should not be marketed as, zero-day
detection.

Sources are public threat-intel categories (malicious npm/PyPI campaigns,
known exfil/C2 infrastructure, abused free-hosting + paste sites, high-risk
TLDs). Lists are intentionally conservative to keep false positives low.
"""

# Package names tied to documented malicious supply-chain campaigns
# (typosquats / dependency-confusion that were published as real attacks).
MALICIOUS_NPM_PACKAGES = {
    "crossenv", "cross-env.js", "babelcli", "d3.js", "fabric-js", "ffmepg",
    "gruntcli", "http-proxy.js", "jquery.js", "mariadb", "mongose", "mssql.js",
    "mssql-node", "nodefabric", "node-fabric", "nodeffmpeg", "nodemailer-js",
    "nodemailer.js", "nodesass", "nodesqlite", "node-sqlite", "node-tkinter",
    "sqlite.js", "sqliter", "sqlserver", "tkinter", "smtpjs", "shadow-deno",
    "electron-native-notify", "eslint-scope", "eslint-config-eslint-scope",
    "flatmap-stream", "event-stream", "rc-validate", "discord.dll",
    "discordi.js", "fix-error", "ua-parser-js",
}

MALICIOUS_PYPI_PACKAGES = {
    "colourama", "djanga", "easyinstall", "libpeshka", "mumpy", "openvc",
    "python-sqlite", "pythonkafka", "pytz3-dev", "telnet", "urlib3", "urllib",
    "django-server", "pymongo3", "pysqlite3", "request", "beautifulsup4",
    "tensorflow-gpu-estimator", "jeIlyfish", "python3-dateutil", "python-mysql",
    "discordpydebug", "fortnite-api-async", "py-cord-dev", "loglib-modules",
}

# Hosts/services frequently abused for exfiltration, C2, or anonymous payload
# hosting. Matched as substrings inside URLs/strings.
C2_EXFIL_HOSTS = {
    "pastebin.com", "hastebin.com", "paste.ee", "ghostbin.com", "rentry.co",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org", "transfer.sh", "0x0.st", "anonfiles.com", "file.io",
    "termbin.com", "glot.io", "webhook.site", "requestbin.com", "pipedream.net",
    "burpcollaborator.net", "interactsh.com", "oast.fun", "oast.pro",
    "oast.live", "oast.site", "dnslog.cn", "ceye.io", "tmpfiles.org",
    "controlc.com", "privatebin.net", "bashupload.com",
}

# High-risk / commonly-abused TLDs (free or cheap, heavily used in malware C2).
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".click", ".link", ".rest", ".zip", ".mov", ".cam", ".surf", ".monster",
}

# Suspicious URL/command patterns (download-and-execute, reverse shells).
MALICIOUS_PATTERNS = [
    ("curl-pipe-shell", r"curl\s+[^\n|]*\|\s*(sh|bash)"),
    ("wget-pipe-shell", r"wget\s+[^\n|]*\|\s*(sh|bash)"),
    ("powershell-download", r"(?i)powershell.*(downloadstring|invoke-webrequest|iwr|webclient)"),
    ("base64-pipe-shell", r"base64\s+(-d|--decode)[^\n|]*\|\s*(sh|bash)"),
    ("reverse-shell-bash", r"bash\s+-i\s+>&?\s*/dev/tcp/"),
    ("python-reverse-shell", r"socket\.socket\([^)]*\).*connect\(\(.*\)\).*(/bin/sh|/bin/bash|cmd\.exe)"),
    ("nc-reverse-shell", r"(?i)\bnc(\.exe)?\s+(-e|-c)\s"),
]
