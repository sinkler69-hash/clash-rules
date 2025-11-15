import yaml

# 1) Читаем rules.yaml
with open("rules.yaml", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

rules = data.get("rules", [])

pac_lines = []


def add(line: str):
    pac_lines.append(line)


# 2) Заголовок PAC
add("function FindProxyForURL(url, host) {")
add("  host = host.toLowerCase();")
add("  url = url.toLowerCase();")
add("")
add('  function PROXY() { return "PROXY 192.168.50.135:7897"; }')  # ТВОЙ ПК + порт Clash
add('  function DIRECT_CONN() { return "DIRECT"; }')
add("")

# 3) Генерация PAC-логики
for rule in rules:
    if not isinstance(rule, str):
        continue

    parts = [p.strip() for p in rule.split(",")]
    if not parts:
        continue

    kind = parts[0]

    # DOMAIN-SUFFIX,example.com,Proxy
    if kind == "DOMAIN-SUFFIX" and len(parts) >= 2:
        domain = parts[1]
        add(f'  if (dnsDomainIs(host, "{domain}")) return PROXY();')

    # DOMAIN-KEYWORD,keyword,Proxy
    elif kind == "DOMAIN-KEYWORD" and len(parts) >= 2:
        kw = parts[1]
        add(f'  if (url.indexOf("{kw}") !== -1) return PROXY();')

    # DOMAIN,example.com,Proxy
    elif kind == "DOMAIN" and len(parts) >= 2:
        domain = parts[1]
        add(f'  if (host === "{domain}") return PROXY();')

    # IP-CIDR в PAC не реализуем, пропускаем (их отрабатывает Clash, PAC живёт без них)
    elif kind == "IP-CIDR":
        continue

    # MATCH,DIRECT — финальное правило, обработаем внизу
    elif kind == "MATCH":
        continue

# финальный дефолт через DIRECT
add("  return DIRECT_CONN();")
add("}")

# 4) Сохраняем universal.pac
with open("universal.pac", "w", encoding="utf-8") as f:
    f.write("\n".join(pac_lines))

print("Generated universal.pac")

# 5) Параллельно генерим ruleset для Clash
#    Clash ожидает формат:
#    payload:
#      - DOMAIN-SUFFIX,example.com,Proxy
#      - ...

payload = []
for rule in rules:
    if not isinstance(rule, str):
        continue

    parts = [p.strip() for p in rule.split(",")]
    if not parts:
        continue

    kind = parts[0]

    # В ruleset не кладём MATCH, чтобы MATCH был только в основном конфиге Clash
    if kind == "MATCH":
        continue

    payload.append(rule)

ruleset_obj = {"payload": payload}

with open("clash-ruleset.yaml", "w", encoding="utf-8") as f:
    yaml.safe_dump(ruleset_obj, f, allow_unicode=True, sort_keys=False)

print("Generated clash-ruleset.yaml")
