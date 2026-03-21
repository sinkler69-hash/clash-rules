import yaml

PAC_PROXY = "PROXY 192.168.50.135:7897"

PROXY_TARGETS = {"PROXY", "MEDIA", "STABLE", "BRAVE_ONLY", "TELEGRAM_STABLE"}
DIRECT_TARGETS = {"DIRECT"}


def normalize_rule(rule: str):
    parts = [p.strip() for p in rule.split(",")]
    if len(parts) < 2:
        return None

    kind = parts[0].upper()
    value = parts[1]

    target = None
    extras = []

    if len(parts) >= 3:
        target = parts[2].upper()
    if len(parts) >= 4:
        extras = parts[3:]

    return {
        "raw": rule.strip(),
        "kind": kind,
        "value": value,
        "target": target,
        "extras": extras,
        "parts": parts,
    }


def pac_action(target: str) -> str:
    if not target:
        return "DIRECT"
    if target.upper() in DIRECT_TARGETS:
        return "DIRECT"
    return "PROXY"


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

# локалка в PAC всегда напрямую
add("  if (isPlainHostName(host) ||")
add('      shExpMatch(host, "*.local") ||')
add('      shExpMatch(host, "*.lan")) {')
add("    return DIRECT_CONN();")
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

    # PROCESS-NAME PAC не понимает
    if kind == "PROCESS-NAME":
        continue

    # MATCH оставляем на самый конец, но тут не используем
    if kind == "MATCH":
        continue

    # IP-CIDR в PAC не поддерживаем
    if kind == "IP-CIDR":
        continue

    # DST-PORT тоже PAC не поддерживает
    if kind == "DST-PORT":
        continue

    if kind == "DOMAIN-SUFFIX":
        if action == "DIRECT":
            add(f'  if (dnsDomainIs(host, "{value}")) return DIRECT_CONN();')
        else:
            add(f'  if (dnsDomainIs(host, "{value}")) return PROXY_CONN();')

    elif kind == "DOMAIN-KEYWORD":
        needle = value.lower()
        if action == "DIRECT":
            add(f'  if (url.indexOf("{needle}") !== -1 || host.indexOf("{needle}") !== -1) return DIRECT_CONN();')
        else:
            add(f'  if (url.indexOf("{needle}") !== -1 || host.indexOf("{needle}") !== -1) return PROXY_CONN();')

    elif kind == "DOMAIN":
        domain = value.lower()
        if action == "DIRECT":
            add(f'  if (host === "{domain}") return DIRECT_CONN();')
        else:
            add(f'  if (host === "{domain}") return PROXY_CONN();')

# дефолт в PAC
add("  return DIRECT_CONN();")
add("}")

with open("universal.pac", "w", encoding="utf-8") as f:
    f.write("\n".join(pac_lines))

print("Generated universal.pac")

# =========================
# Clash ruleset generation
# =========================
payload = []

for raw_rule in rules:
    if not isinstance(raw_rule, str):
        continue

    rule = normalize_rule(raw_rule)
    if not rule:
        continue

    if rule["kind"] == "MATCH":
        continue

    payload.append(rule["raw"])

ruleset_obj = {"payload": payload}

with open("clash-ruleset.yaml", "w", encoding="utf-8") as f:
    yaml.safe_dump(ruleset_obj, f, allow_unicode=True, sort_keys=False)

print("Generated clash-ruleset.yaml")
