#!/usr/bin/env python3
# ============================================================
# Burp 交互式分析器 v3
# ============================================================
# 用法: python3 analyzer_tui.py burp.xml
#
# 在 v2 基础上增加交互：
#   - 列出高疑点，按编号选择查看详情
#   - 详情包含：在 burp.xml 里的第几条（item索引）、关键参数
#   - 单独的"参数比对模式"，横向对比所有关键参数+来源
#
# ★ 学习提示：这个脚本的新东西是"交互循环"。
#   核心模式是：while True → 显示菜单 → 读输入 → 分支处理。
#   这是所有命令行交互程序的骨架，看懂这个你能写任何TUI。
#
# ★ index 字段说明：item 在 XML 里的出现顺序（从1开始）。
#   它对应你 Burp HTTP history 里的相对顺序，不是 history 的 # 号
#   （Burp的#号是全局递增的，导出后丢失）。用它在导出的xml里定位，
#   或按 method+url 回 Burp 搜索。
# ============================================================

import sys
import base64
import re
import xml.etree.ElementTree as ET
from collections import Counter

# ---- 规则表（和 v2 一致，改这里加新漏洞类型）----
RULES = {
    "水平越权/IDOR": {
        "keywords": ["orderid", "orderno", "ordersn", "order_id", "order_no",
                     "addressid", "address_id", "couponid", "voucherid"],
        "severity": 3, "likelihood": 4,
        "why": "URL/body里带资源ID。换成别人的ID能拿到数据=越权。"
    },
    "垂直越权": {
        "keywords": ["isadmin", "role", "usertype", "user_type", "userlevel",
                     "user_group", "permission", "auth_level"],
        "severity": 4, "likelihood": 3,
        "why": "请求里有角色/权限字段。改大权限值看能否提权。"
    },
    "未授权访问": {
        "keywords": ["/admin", "/manage", "/backstage", "/internal",
                     "/debug", "/actuator", "/console", "/sys/"],
        "severity": 4, "likelihood": 3,
        "why": "管理类路径。删掉Cookie直接访问看是否需要鉴权。"
    },
    "价格/金额篡改": {
        "keywords": ["amount", "price", "totalamount", "payamount",
                     "money", "fee", "discount", "totalfee"],
        "severity": 4, "likelihood": 4,
        "why": "提交类请求带金额字段。改低/改负看服务端是否重新验价。"
    },
    "文件操作/路径穿越": {
        "keywords": ["filename=", "filepath=", "file=", "path=",
                     "filename\":", "download", "upload"],
        "severity": 3, "likelihood": 3,
        "why": "文件参数。试 ../ 路径穿越或改文件类型绕过上传限制。"
    },
    "SSRF/URL重定向": {
        "keywords": ["url=", "redirect=", "redirect_uri", "callback=",
                     "returnurl", "return_url", "target=", "next="],
        "severity": 3, "likelihood": 3,
        "why": "参数值是URL。改成内网地址测SSRF，改成外站测开放重定向。"
    },
    "敏感信息泄露": {
        "keywords": ["phone", "mobile", "idcard", "id_card", "email",
                     "realname", "real_name", "bankcard", "address"],
        "severity": 2, "likelihood": 3,
        "why": "响应可能含PII。结合越权时危害升级（批量拖库）。"
    },
}


def decode(text):
    if not text:
        return ""
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return text


def split_body(raw_http):
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_http:
            return raw_http.split(sep, 1)[1]
    return ""


def normalize_path(url):
    path = url.split("?")[0]
    path = re.sub(r"/\d{4,}", "/{ID}", path)
    path = re.sub(r"^https?://[^/]+", "", path)
    return path or "/"


def extract_params(url, body):
    """
    抽出这个请求里所有的 key=value / "key":value 参数。
    返回 [(参数名, 参数值), ...]
    ★ 学习提示：两个正则分别处理URL查询串和JSON body。
      想支持更多格式（比如 XML body），在这里加正则。
    """
    params = []
    # URL query: ?a=1&b=2
    for k, v in re.findall(r"[?&]([a-zA-Z_][\w]*)=([^&\s]*)", url):
        params.append((k, v))
    # JSON body: "key":"value" 或 "key":value
    for k, v in re.findall(r'"([a-zA-Z_][\w]*)"\s*:\s*"?([^",}\]]*)"?', body):
        params.append((k, v.strip()))
    return params


def parse(xml_path):
    """解析XML，返回 findings 列表 + 频率统计"""
    root = ET.parse(xml_path).getroot()
    findings = []
    endpoint_counter = Counter()
    param_counter = Counter()
    total = 0

    for idx, item in enumerate(root.findall("item"), start=1):
        total += 1
        url = item.findtext("url") or ""
        method = item.findtext("method") or ""
        status = item.findtext("status") or ""
        raw_req = decode(item.findtext("request"))
        body = split_body(raw_req)
        haystack = (url + " " + body).lower()

        endpoint_counter[normalize_path(url)] += 1
        params = extract_params(url, body)
        for k, _ in params:
            param_counter[k.lower()] += 1

        for vuln_type, rule in RULES.items():
            hit = next((kw for kw in rule["keywords"] if kw in haystack), None)
            if not hit:
                continue
            priority = rule["severity"] * rule["likelihood"]
            if method == "POST":
                priority += 2
            findings.append({
                "index": idx,                 # 在xml里的第几条
                "type": vuln_type,
                "method": method,
                "url": url,
                "status": status,
                "hit": hit,
                "severity": rule["severity"],
                "likelihood": rule["likelihood"],
                "priority": priority,
                "why": rule["why"],
                "params": params,
                "body": body,
            })

    # 同接口同类型去重，保留优先级最高的
    dedup = {}
    for f in findings:
        key = (normalize_path(f["url"]), f["type"])
        if key not in dedup or f["priority"] > dedup[key]["priority"]:
            dedup[key] = f
    findings = sorted(dedup.values(), key=lambda x: x["priority"], reverse=True)
    return findings, endpoint_counter, param_counter, total


# ============================================================
# 交互界面
# ============================================================
def show_list(findings):
    """打印高疑点列表"""
    print("\n" + "=" * 64)
    print("  高疑点列表（按优先级排序）")
    print("=" * 64)
    for i, f in enumerate(findings, start=1):
        bar = "■" * f["priority"] + "□" * (27 - f["priority"])
        print(f"[{i:>2}] 优先级{f['priority']:>2} {bar}")
        print(f"     {f['type']} | [{f['method']}] {f['url'][:70]}")
    print("-" * 64)


def show_detail(f):
    """显示单条详情"""
    print("\n" + "=" * 64)
    print(f"  详情  |  类型: {f['type']}")
    print("=" * 64)
    print(f"  在 burp.xml 里的位置 : 第 {f['index']} 条 item")
    print(f"  方法                 : {f['method']}")
    print(f"  URL                  : {f['url']}")
    print(f"  状态码               : {f['status']}")
    print(f"  命中关键词           : {f['hit']}")
    print(f"  威胁/可能/优先级     : {f['severity']} / {f['likelihood']} / {f['priority']}")
    print(f"  为什么值得测         : {f['why']}")
    print("-" * 64)
    print("  关键参数：")
    if f["params"]:
        for k, v in f["params"]:
            vv = (v[:50] + "...") if len(v) > 50 else v
            print(f"    {k:<22} = {vv}")
    else:
        print("    （无参数，可能是无body的GET）")
    print("-" * 64)
    print("  ★ 回 Burp 定位方法：HTTP history 搜索框输入 URL 路径关键词，")
    print(f"    或按方法+路径过滤： {f['method']}  {normalize_path(f['url'])}")
    print("=" * 64)


def show_param_compare(findings):
    """参数比对模式：所有关键参数横向列出 + 来源"""
    print("\n" + "=" * 70)
    print("  参数比对模式  |  所有高疑点的关键参数 + 来源")
    print("=" * 70)
    # 收集：参数名 -> [(值, 来源接口, xml第几条), ...]
    table = {}
    for f in findings:
        for k, v in f["params"]:
            table.setdefault(k, []).append(
                (v, normalize_path(f["url"]), f["index"])
            )
    # 优先展示在多个接口出现的参数（最值得比对的）
    sorted_params = sorted(table.items(), key=lambda x: len(x[1]), reverse=True)
    for pname, occurrences in sorted_params:
        print(f"\n● 参数: {pname}   （出现 {len(occurrences)} 次）")
        for v, src, idx in occurrences:
            vv = (v[:40] + "...") if len(v) > 40 else (v or "(空)")
            print(f"    值={vv:<43} 来源={src}  [xml第{idx}条]")
    print("\n" + "=" * 70)


def main():
    if len(sys.argv) < 2:
        print("用法: python3 analyzer_tui.py burp.xml")
        sys.exit(1)

    try:
        findings, ep_cnt, pm_cnt, total = parse(sys.argv[1])
    except ET.ParseError as e:
        print(f"[!] XML解析失败: {e}")
        sys.exit(1)

    print(f"\n[*] 共解析 {total} 条请求，命中 {len(findings)} 个去重后的高疑点")

    # ---- 交互主循环 ----
    # ★ 学习提示：这就是TUI的骨架。while True 不停循环，
    #   每轮显示菜单→读输入→根据输入分支。想加新功能就加一个分支。
    while True:
        show_list(findings)
        print("操作：输入编号看详情 | p=参数比对模式 | q=退出")
        choice = input(">>> ").strip().lower()

        if choice == "q":
            print("退出。")
            break
        elif choice == "p":
            show_param_compare(findings)
            input("\n按回车返回列表...")
        elif choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(findings):
                show_detail(findings[n - 1])
                input("\n按回车返回列表...")
            else:
                print("编号超出范围。")
        else:
            print("无效输入。")


if __name__ == "__main__":
    main()

# ============================================================
# 后期扩展思路（写给你自己）：
#   1. 加"导出选中条目"功能：在主循环加分支 's'，把选中的
#      finding 写成文件，方便记笔记 / 写报告。
#   2. 加 Response 分析：parse() 里解码 item.findtext("response")，
#      用正则在响应里找手机号 \d{11} / 身份证，命中=信息泄露确认。
#   3. 加颜色：用 ANSI 转义码 \033[31m...\033[0m 让高优先级标红。
#   4. 参数比对模式可以加"只看值不同的参数"——同名参数不同值
#      往往是越权/篡改的信号。
#   想深入：搜 "python curses" 可做成真正的全屏TUI（带光标移动）。
# ============================================================