import yaml

with open("rules.yaml", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

rules = data.get("rules", [])

pac_lines = []


def add(line: str):
    pac_lines.append(line)


add("function FindProxyForURL(url, host) {")
add("  host = host.toLowerCase();")
add("  url = url.toLowerCase();")
add("")
add('  function PROXY() { return "PROXY 192.168.50.135:7897"; }')
add('  function DIRECT_CONN() { return "DIRECT"; }')
add("")

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

    # IP-CIDR,....  → PAC этим не занимается, пропускаем
    elif kind == "IP-CIDR":
        continue

    # RULE-SET и прочие — просто игнорируем
    elif kind == "RULE-SET":
        continue

    # MATCH,DIRECT — финальное правило, обработаем ниже
    elif kind == "MATCH":
        # ничего не добавляем тут, финальный return будет внизу
        continue

# финальное правило по умолчанию — DIRECT
add("  return DIRECT_CONN();")
add("}")

with open("universal.pac", "w", encoding="utf-8") as f:
    f.write("\n".join(pac_lines))

print("Generated universal.pac")
