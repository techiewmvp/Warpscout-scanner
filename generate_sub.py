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

# 如果没有，默认给一组官方高质量端点兜底
if not target_endpoints:
    target_endpoints = [
        "162.159.199.144:4443", "162.159.198.88:8443",
        "162.159.198.187:1701", "162.159.198.214:8095"
    ]

# 限制穿透端点数量，避免笛卡尔积组合膨胀太多
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

# 4. 组装代理节点（第一层 MASQUE 基础通道 + 第二层 Opera 套娃节点）
underlying_proxies = []
underlying_names = []

for idx, ep in enumerate(target_endpoints, 1):
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    name = f"底座-H2-{idx:02d}"
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
    # 取前 2 个落地服务器
    for land in landings[:2]:
        for base_name in underlying_names:
            c_name = f"{land['tag']}@{base_name}"
            region_groups[region].append(c_name)
            combo_proxies.append(
                f"  - {{name: '{c_name}', type: http, server: {land['ip']}, port: {land['port']}, "
                f"username: {land['user']}, password: {land['pw']}, tls: true, sni: {land['host']}, "
                f"skip-cert-verify: false, dialer-proxy: '{base_name}'}}"
            )

# 5. 构建完整 YAML 配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "tcp-concurrent: true",
    "global-client-fingerprint: chrome",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "  fallback:",
    "    - 1.1.1.1",
    "",
    "proxies:"
] + underlying_proxies + combo_proxies

# 6. 策略组结构（支持选大区、支持自动优选、支持随时切回大带宽纯 WARP）
yaml_lines.extend([
    "",
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
    "      - ⚡ 亚洲线路",
    "      - 🌍 欧洲线路",
    "      - 🗽 美洲线路",
    "      - 🚀 WARP极速直连",
    "      - DIRECT",
    "",
    "  - name: ⚡ 自动优选",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:",
    "      - ⚡ 亚洲线路",
    "      - 🌍 欧洲线路",
    "      - 🗽 美洲线路",
    "      - 🚀 WARP极速直连",
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - ⚡ 亚洲线路",
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - 🚀 默认代理",
    "",
    "  - name: 📺 国际媒体",
    "    type: select",
    "    proxies:",
    "      - ⚡ 亚洲线路",
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - 🚀 默认代理",
    "",
    "  - name: 🚀 WARP极速直连",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in underlying_names] + [
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
    "  - name: 🌍 欧洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["欧洲"]] + [
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
    "  - name: 🛑 广告拦截",
    "    type: select",
    "    proxies:",
    "      - REJECT",
    "      - DIRECT",
    ""
])

# 7. 分流规则
yaml_lines.extend([
    "rules:",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功融合套娃架构！已生成完整聚合订阅至: {OUTPUT_PATH}")
