import concurrent.futures
import copy
import os
import socket
import urllib.request

import yaml


NODES_DIR = "nodes"
TXT_OUTPUT_FILE = os.path.join(NODES_DIR, "simple.txt")
CLASH_OUTPUT_FILE = os.path.join(NODES_DIR, "clashmeta.yaml")

TXT_TARGETS = (
    "yudou66",
    "nodefree",
    "v2rayshare",
    "wenode",
    "nodev2ray",
)

YAML_TARGETS = (
    "yudou66",
    "nodefree",
    "v2rayshare",
    "wenode",
    "nodev2ray",
)

EXTERNAL_YAML_SOURCES = {
    "itxve": "https://cdn.jsdelivr.net/gh/itxve/fetch-clash-node/node/ClashNode.yaml",
}

SELECT_GROUP = "\U0001f680 \u8282\u70b9\u9009\u62e9"
AUTO_GROUP = "\u267b\ufe0f \u81ea\u52a8\u9009\u62e9"


def _read_text(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return file.read().strip()


def _load_yaml_file(path):
    text = _read_text(path)
    if not text:
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        print(f"Skipping invalid yaml {path}: {exc}")
        return {}
    return data if isinstance(data, dict) else {}


def _load_external_yaml(name, url):
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 FreeNodes"}
        )
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read().decode("utf-8", errors="ignore")
        data = yaml.safe_load(body)
        if isinstance(data, dict):
            print(f"Loaded external yaml {name}: {url}")
            return data
    except Exception as exc:
        print(f"Skipping external yaml {name}: {exc}")
    return {}


def _proxy_key(proxy):
    keys = (
        "type",
        "server",
        "port",
        "uuid",
        "password",
        "cipher",
        "network",
        "sni",
        "servername",
        "ws-opts",
        "grpc-opts",
    )
    return tuple(str(proxy.get(key, "")) for key in keys)


def _unique_name(base, used):
    name = str(base or "proxy")
    if name not in used:
        used.add(name)
        return name
    idx = 2
    while f"{name}_{idx}" in used:
        idx += 1
    unique = f"{name}_{idx}"
    used.add(unique)
    return unique


def _tcp_available(proxy):
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        with socket.create_connection((str(server), int(port)), timeout=2.5):
            return True
    except Exception:
        return False


def _filter_tcp(proxies):
    if os.getenv("CHECK_TCP", "1") == "0":
        return proxies
    if not proxies:
        return proxies
    max_workers = min(64, max(1, len(proxies)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        checks = list(executor.map(_tcp_available, proxies))
    filtered = [proxy for proxy, ok in zip(proxies, checks) if ok]
    print(f"TCP filter kept {len(filtered)}/{len(proxies)} proxies")
    return filtered or proxies


def _collect_proxies():
    proxies = []
    for target in YAML_TARGETS:
        data = _load_yaml_file(os.path.join(NODES_DIR, f"{target}.yaml"))
        items = data.get("proxies", [])
        if isinstance(items, list):
            print(f"Loaded {len(items)} yaml proxies from {target}")
            proxies.extend(items)

    for name, url in EXTERNAL_YAML_SOURCES.items():
        data = _load_external_yaml(name, url)
        items = data.get("proxies", [])
        if isinstance(items, list):
            print(f"Loaded {len(items)} yaml proxies from external {name}")
            proxies.extend(items)

    unique = []
    seen = set()
    used_names = set()
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        key = _proxy_key(proxy)
        if key in seen:
            continue
        seen.add(key)
        item = copy.deepcopy(proxy)
        item["name"] = _unique_name(item.get("name"), used_names)
        unique.append(item)
    print(f"Deduplicated yaml proxies: {len(unique)}")
    return _filter_tcp(unique)


def _write_clash(proxies):
    names = [proxy["name"] for proxy in proxies]
    data = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": SELECT_GROUP,
                "type": "select",
                "proxies": [AUTO_GROUP, "DIRECT", *names],
            },
            {
                "name": AUTO_GROUP,
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names,
            },
        ],
        "rules": [f"MATCH,{SELECT_GROUP}"],
    }
    with open(CLASH_OUTPUT_FILE, "w", encoding="utf-8") as file:
        yaml.safe_dump(data, file, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"Successfully merged clash config to {CLASH_OUTPUT_FILE}")


def merge_txt_configs():
    merged_content = []
    seen = set()
    for target in TXT_TARGETS:
        content = _read_text(os.path.join(NODES_DIR, f"{target}.txt"))
        if not content:
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            merged_content.append(line)

    with open(TXT_OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(merged_content))
    print(f"Successfully merged txt configs to {TXT_OUTPUT_FILE}")


def merge_configs():
    if not os.path.exists(NODES_DIR):
        os.mkdir(NODES_DIR)
    merge_txt_configs()
    _write_clash(_collect_proxies())


if __name__ == "__main__":
    merge_configs()
