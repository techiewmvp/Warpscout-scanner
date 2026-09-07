import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

SNI_POOL = [
    "www.apple.com",
    "www.visa.cn",
    "www.tesla.cn",
    "www.mastercard.com.cn"
]

# 1. 提取 WARP 凭据
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 2. 读取本地优选的极速穿透端点 (endpoints.txt)
target_endpoints = []
if os.path.exists(TXT_PATH):
    print(f"[INFO] 载入本地优选端点池: {TXT_PATH}")
    with open(TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.match(r'^((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})', line)
                if m and m.group(1) not in target_endpoints:
                    target_endpoints.append(m.group(1))

if not target_endpoints:
    target_endpoints = [
        "162.159.199.144:4443", "162.159.198.88:8443",
        "162.159.198.187:1701", "162.159.198.214:8095"
    ]

target_endpoints = target_endpoints[:8]

# 3. 解析 Opera 落地节点信息
def parse_opera(filename, region_name):
    path = os.path.join(CURRENT_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    login_m = re.search(r"Proxy login: (\S+)", content)
    pw_m = re.search(r"Proxy password: (\S+)", content)
    if not (login_m and pw_m):
        return None
    
    user, pw = login_m.group(1), pw_m.group(1)
    landings = []
    seq = 1
    for line in content.splitlines():
        m = re.match(r"^([\w.-]+\.sec-tunnel\.com),([\d.]+),(\d+)$", line.strip())
        if m:
            host, srv_ip, port = m.groups()
            landings.append({
                "tag": f"{region_name}{seq}",
                "host": host,
                "ip": srv_ip,
                "port": port,
                "user": user,
                "pw": pw
            })
            seq += 1
    return landings

opera_regions = {
    "亚洲": parse_opera("opera_as.txt", "亚洲"),
    "欧洲": parse_opera("opera_eu.txt", "欧洲"),
    "美洲": parse_opera("opera_am.txt", "美洲")
}

# 4. 组装代理节点
underlying_proxies = []
underlying_names = []

for idx, ep in enumerate(target_endpoints, 1):
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    name = f"WARP直连-{idx:02d}"
    underlying_names.append(name)
    underlying_proxies.extend([
        f"  - name: '{name}'",
        "    type: masque",
        f"    server: '{host}'",
        f"    port: {port}",
        "    network: h2",
        f"    sni: '{assigned_sni}'",
        f"    private-key: '{private_key}'",
        f"    public-key: '{public_key}'",
        f"    ip: '{ip}'",
    ])
    if ipv6:
        underlying_proxies.append(f"    ipv6: '{ipv6}'")
    underlying_proxies.extend([
        "    udp: true",
        "    remote-dns-resolve: true",
        "    dns: [1.1.1.1, 1.0.0.1]",
        ""
    ])

# 笛卡尔积组合套娃节点
combo_proxies = []
region_groups = {"亚洲": [], "欧洲": [], "美洲": []}

for region, landings in opera_regions.items():
    if not landings:
        continue
    for land in landings[:2]:
        for base_name in underlying_names:
            c_name = f"{land['tag']}@{base_name}"
            region_groups[region].append(c_name)
            combo_proxies.append(
                f"  - {{name: '{c_name}', type: http, server: {land['ip']}, port: {land['port']}, "
                f"username: {land['user']}, password: {land['pw']}, tls: true, sni: {land['host']}, "
                f"skip-cert-verify: false, dialer-proxy: '{base_name}'}}"
            )

# 5. 构建完整 YAML 配置（引入网友成熟的 Sniffer 与 精准分流 DNS 策略）
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "ipv6: false",
    "unified-delay: true",
    "tcp-concurrent: true",
    "",
    "# 开启嗅探，防止访问 Google / Gemini 时因 CDN 调度或 FakeIP 导致分流脱轨",
    "sniffer:",
    "  enable: true",
    "  sniff:",
    "    HTTP:",
    "      ports: [80, 8080-8880]",
    "      override-destination: true",
    "    TLS:",
    "      ports: [443, 8443]",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  default-nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "  nameserver:",
    "    - https://223.5.5.5/dns-query",
    "    - https://1.12.12.12/dns-query",
    "  proxy-server-nameserver:",
    "    - https://223.5.5.5/dns-query",
    "  nameserver-policy:",
    "    'geosite:cn,private':",
    "      - https://223.5.5.5/dns-query",
    "    'geosite:geolocation-!cn':",
    "      - https://1.1.1.1/dns-query",
    "      - https://8.8.8.8/dns-query",
    "",
    "proxies:"
] + underlying_proxies + combo_proxies

# 6. 精细化策略组架构
yaml_lines.extend([
    "",
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ WARP极速优选",
    "      - 🤖 人工智能套娃",
    "      - DIRECT",
] + [f"      - '{name}'" for name in underlying_names] + [
    "",
    "  - name: ⚡ WARP极速优选",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in underlying_names] + [
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - 🤖 人工智能套娃",
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - ⚡ 亚洲线路",
    "      - ⚡ WARP极速优选",
    "",
    "  - name: 🤖 人工智能套娃",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:",
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - ⚡ 亚洲线路",
    "",
    "  - name: 🗽 美洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["美洲"]] + [
    "",
    "  - name: 🌍 欧洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["欧洲"]] + [
    "",
    "  - name: ⚡ 亚洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["亚洲"]] + [
    "",
    "  - name: 📺 国际媒体",
    "    type: select",
    "    proxies:",
    "      - ⚡ WARP极速优选",
    "      - 🚀 默认代理",
    "",
    "  - name: 🛑 广告拦截",
    "    type: select",
    "    proxies:",
    "      - REJECT",
    "      - DIRECT",
    ""
])

# 7. 全场景高精分流规则（重点修复：阻断 QUIC 并补全 Gemini 规则）
yaml_lines.extend([
    "rules:",
    "  # 【最核心修复】阻断 UDP 443 (QUIC)，防止浏览器尝试 HTTP/3 连接导致 Gemini 转圈白屏",
    "  - AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    "",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 1. 规避 BT/P2P 下载",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 2. 广告拦截",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  # 3. 【核心修复】Gemini 与 Google AI 完整生态全域名强制走套娃",
    "  - DOMAIN-SUFFIX,bard.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,gemini.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,aistudio.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,ai.google.dev,🤖 人工智能",
    "  - DOMAIN-SUFFIX,makersuite.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,deepmind.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,deepmind.google,🤖 人工智能",
    "  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,alkalimakersuite-pa.googleapis.com,🤖 人工智能",
    "  - DOMAIN-KEYWORD,gemini,🤖 人工智能",
    "  - DOMAIN-KEYWORD,bard,🤖 人工智能",
    "  - DOMAIN-KEYWORD,colab,🤖 人工智能",
    "",
    "  # OpenAI / ChatGPT -> 走套娃",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - DOMAIN-SUFFIX,chatgpt.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "",
    "  # Claude -> 走套娃",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,claude.ai,🤖 人工智能",
    "",
    "  # 4. Google 基础底层依赖（走代理，防污染）",
    "  - DOMAIN-SUFFIX,googleapis.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,gstatic.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,google.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,googleusercontent.com,🚀 默认代理",
    "",
    "  # 5. 海外媒体",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  # 6. 大陆直连白名单",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 7. 兜底策略",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 修复完毕：成功注入 QUIC 阻断、Sniffer 嗅探及 Gemini 完整规则！")
print(f"[OK] 文件已更新至: {OUTPUT_PATH}")
