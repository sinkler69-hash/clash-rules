import yaml

PAC_PROXY = "PROXY 192.168.50.135:7897"

DIRECT_TARGETS = {"DIRECT"}
MEDIA_TARGETS = {"MEDIA"}
STABLE_TARGETS = {"STABLE"}


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

    if kind in {"PROCESS-NAME", "MATCH", "IP-CIDR", "DST-PORT"}:
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

add("  return DIRECT_CONN();")
add("}")

with open("universal.pac", "w", encoding="utf-8") as f:
    f.write("\n".join(pac_lines))

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
