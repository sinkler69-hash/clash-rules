import yaml

PAC_PROXY = "PROXY 192.168.50.135:7897"

DIRECT_TARGETS = {"DIRECT"}
MEDIA_TARGETS = {"MEDIA"}
STABLE_TARGETS = {"STABLE"}

# Apple-сервисы на iOS через PAC/HTTP proxy часто ломают App Store,
# iCloud, обновления и авторизацию. Держим их hardcoded DIRECT
# внутри генератора, чтобы это не зависело от rules.yaml и всегда
# попадало в начало universal.pac до dnsResolve() и proxy-правил.
APPLE_DIRECT_DOMAINS = [
    "apple.com",
    "icloud.com",
    "itunes.com",
    "mzstatic.com",
    "cdn-apple.com",
    "aaplimg.com",
    "apple-dns.net",
    "apple-cloudkit.com",
    "apps.apple.com",
    "appstoreconnect.apple.com",
    "app-attest.apple.com",
    "akadns.net",
]


def normalize_rule(rule: str):
    parts = [p.strip() for p in rule.split(",")]
    if len(parts) < 2:
        return None

    kind = parts[0].upper()
    value = parts[1]
    target = parts[2].upper() if len(parts) >= 3 else None
    extras = parts[3:] if len(parts) >= 4 else []

    return {
        "raw": rule.strip(),
        "kind": kind,
        "value": value,
        "target": target,
        "extras": extras,
        "parts": parts,
    }


def pac_action(target: str) -> str:
    if target and target.upper() in DIRECT_TARGETS:
        return "DIRECT"
    return "PROXY"


def clash_bucket(rule: dict) -> str | None:
    kind = rule["kind"]
    target = rule["target"]

    if kind in {"MATCH", "PROCESS-NAME"}:
        return None

    if target and target.upper() in DIRECT_TARGETS:
        return None

    if target and target.upper() in MEDIA_TARGETS:
        return "MEDIA"

    if target and target.upper() in STABLE_TARGETS:
        return "STABLE"

    return "PROXY"


def provider_rule_text(rule: dict) -> str:
    """
    Для multi-provider rulesets убираем target.
    Было: DOMAIN-KEYWORD,rutracker,Proxy
    Стало: DOMAIN-KEYWORD,rutracker
    """
    kind = rule["kind"]
    value = rule["value"]
    extras = rule["extras"]

    parts = [kind, value]
    if extras:
        parts.extend(extras)

    return ",".join(parts)


def legacy_rule_text(rule: dict) -> str | None:
    """
    Для legacy clash-ruleset.yaml:
    - DIRECT сохраняем как DIRECT
    - всё остальное делаем Proxy
    - PROCESS-NAME и MATCH не тащим
    """
    kind = rule["kind"]
    value = rule["value"]
    target = rule["target"]
    extras = rule["extras"]

    if kind in {"MATCH", "PROCESS-NAME"}:
        return None

    if target and target.upper() in DIRECT_TARGETS:
        parts = [kind, value, "DIRECT"]
    else:
        parts = [kind, value, "Proxy"]

    if extras:
        parts.extend(extras)

    return ",".join(parts)


def js_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').lower()


def emit_pac_domain_suffix(add, value: str, action: str):
    v = js_escape(value)
    ret = "DIRECT_CONN()" if action == "DIRECT" else "PROXY_CONN()"
    add(f'  if (host === "{v}" || shExpMatch(host, "*.{v}")) return {ret};')


def emit_pac_domain(add, value: str, action: str):
    v = js_escape(value)
    ret = "DIRECT_CONN()" if action == "DIRECT" else "PROXY_CONN()"
    add(f'  if (host === "{v}") return {ret};')


def emit_pac_domain_keyword(add, value: str, action: str):
    v = js_escape(value)
    ret = "DIRECT_CONN()" if action == "DIRECT" else "PROXY_CONN()"
    add(f'  if (host.indexOf("{v}") !== -1) return {ret};')


with open("rules.yaml", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

rules = data.get("rules", [])

# =========================
# PAC generation
# =========================
pac_lines = []


def add(line: str):
    pac_lines.append(line)


add("function FindProxyForURL(url, host) {")
add('  host = (host || "").toLowerCase();')
add('  url = (url || "").toLowerCase();')
add("")
add(f'  function PROXY_CONN() {{ return "{PAC_PROXY}"; }}')
add('  function DIRECT_CONN() { return "DIRECT"; }')
add("")

# Apple / App Store / iCloud always DIRECT for iOS PAC.
# Важно: этот блок стоит ДО dnsResolve(), чтобы iOS не подвисал
# и не отправлял Apple CDN через explicit proxy.
add("  // Apple / App Store / iCloud — always DIRECT")
for domain in APPLE_DIRECT_DOMAINS:
    emit_pac_domain_suffix(add, domain, "DIRECT")
add("")

# Local names always DIRECT
add("  if (isPlainHostName(host) ||")
add('      shExpMatch(host, "*.local") ||')
add('      shExpMatch(host, "*.lan")) {')
add("    return DIRECT_CONN();")
add("  }")
add("")

# RFC1918 / loopback always DIRECT
add("  var resolved = dnsResolve(host);")
add("  if (resolved) {")
add('    if (isInNet(resolved, "127.0.0.0", "255.0.0.0") ||')
add('        isInNet(resolved, "10.0.0.0", "255.0.0.0") ||')
add('        isInNet(resolved, "172.16.0.0", "255.240.0.0") ||')
add('        isInNet(resolved, "192.168.0.0", "255.255.0.0")) {')
add("      return DIRECT_CONN();")
add("    }")
add("  }")
add("")

for raw_rule in rules:
    if not isinstance(raw_rule, str):
        continue

    rule = normalize_rule(raw_rule)
    if not rule:
        continue

    kind = rule["kind"]
    value = rule["value"]
    target = rule["target"]
    action = pac_action(target)

    # Apple уже добавлен отдельным hardcoded DIRECT-блоком выше.
    # Пропускаем дубли из rules.yaml, чтобы PAC был чище.
    if kind in {"DOMAIN-SUFFIX", "DOMAIN"} and value.lower() in APPLE_DIRECT_DOMAINS:
        continue

    # Эти типы не имеют смысла для PAC
    if kind in {"PROCESS-NAME", "MATCH", "IP-CIDR", "DST-PORT"}:
        continue

    if kind == "DOMAIN-SUFFIX":
        emit_pac_domain_suffix(add, value, action)

    elif kind == "DOMAIN-KEYWORD":
        emit_pac_domain_keyword(add, value, action)

    elif kind == "DOMAIN":
        emit_pac_domain(add, value, action)

add("  return DIRECT_CONN();")
add("}")

with open("universal.pac", "w", encoding="utf-8") as f:
    f.write("\n".join(pac_lines) + "\n")

print("Generated universal.pac")

# =========================
# Multi-provider Clash rulesets
# =========================
group_payloads = {
    "MEDIA": [],
    "STABLE": [],
    "PROXY": [],
}

for raw_rule in rules:
    if not isinstance(raw_rule, str):
        continue

    rule = normalize_rule(raw_rule)
    if not rule:
        continue

    bucket = clash_bucket(rule)
    if not bucket:
        continue

    group_payloads[bucket].append(provider_rule_text(rule))

output_files = {
    "MEDIA": "media-ruleset.yaml",
    "STABLE": "stable-ruleset.yaml",
    "PROXY": "proxy-ruleset.yaml",
}

for group, filename in output_files.items():
    ruleset_obj = {"payload": group_payloads[group]}
    with open(filename, "w", encoding="utf-8") as f:
        yaml.safe_dump(ruleset_obj, f, allow_unicode=True, sort_keys=False)
    print(f"Generated {filename}")

# =========================
# Legacy Clash ruleset for simple profile
# =========================
legacy_payload = []

for raw_rule in rules:
    if not isinstance(raw_rule, str):
        continue

    rule = normalize_rule(raw_rule)
    if not rule:
        continue

    text = legacy_rule_text(rule)
    if text:
        legacy_payload.append(text)

legacy_ruleset_obj = {"payload": legacy_payload}

with open("clash-ruleset.yaml", "w", encoding="utf-8") as f:
    yaml.safe_dump(legacy_ruleset_obj, f, allow_unicode=True, sort_keys=False)

print("Generated clash-ruleset.yaml")
