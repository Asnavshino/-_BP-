#!/usr/bin/env python3
# ============================================================
# Burp 交互式分析器 v4
# ============================================================
# 用法: python3 analyzer_tui.py burp.xml
#
# 相比 v3 的升级（对应你指出的缺口）：
#   [缺口1] 误报过滤：命中后再判断上下文（是否提交类请求、
#           参数值是否像金额/ID），降低噪音
#   [缺口2] Response分析：解码响应，正则找手机号/身份证/邮箱，
#           找堆栈/SQL报错，命中则把优先级加分并标注
#   [缺口5] 状态码参与打分：200可测性高加分，404/500降分
#   新功能1：详情里显示"关联请求"（参数值相同的其他请求）
#   新功能2：业务链视图（按xml顺序展示完整调用链）
#   新功能3：导出当前详情涉及的请求为新xml
#
# ★ 学习提示：这一版最值得学的是 enrich_with_response()——
#   它展示了"信号增强"：一个点可疑不可疑不是单维度决定的，
#   要把请求、响应、状态码多个信号叠加。真实扫描器(nuclei)
#   的matcher就是这个思路的复杂版。
# ============================================================

import sys
import base64
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

# ---- 规则表 ----
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

# ---- Response里用来确认信号的正则 ----
# ★ 学习提示：请求可疑只是怀疑，响应里真出现敏感数据才是实锤。
RESP_PATTERNS = {
    "手机号":   re.compile(r'1[3-9]\d{9}'),
    "身份证":   re.compile(r'\d{17}[\dXx]'),
    "邮箱":     re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
    "SQL报错":  re.compile(r'(SQLException|syntax error|ORA-\d{5}|mysql_fetch)', re.I),
    "堆栈泄露": re.compile(r'(at java\.|Traceback \(most recent|\.java:\d+\)|Exception in)'),
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
    params = []
    for k, v in re.findall(r"[?&]([a-zA-Z_][\w]*)=([^&\s]*)", url):
        params.append((k, v))
    for k, v in re.findall(r'"([a-zA-Z_][\w]*)"\s*:\s*"?([^",}\]]*)"?', body):
        params.append((k, v.strip()))
    return params


def is_false_positive(vuln_type, method, params, hit):
    """
    [缺口1] 误报过滤。命中关键词只是必要条件不是充分条件，
    用上下文二次确认。返回True=判定误报丢弃。
    ★ 扩展点：每种漏洞可有自己的确认逻辑，往这加if分支。
    """
    if vuln_type == "价格/金额篡改":
        # 非提交类(GET且无body参数)多半是查询展示，降噪
        if method == "GET" and not params:
            return True
    if vuln_type == "水平越权/IDOR":
        # 命中的ID参数值为空，没法测，过滤
        for k, v in params:
            if hit in k.lower() and v.strip() in ("", "null", "0"):
                return True
    return False


def enrich_with_response(finding, resp_body, status):
    """
    [缺口2+5] 用响应内容和状态码增强判断（信号叠加）。
    """
    bonus = 0
    confirmations = []
    for name, pat in RESP_PATTERNS.items():
        m = pat.search(resp_body)
        if m:
            confirmations.append(f"{name}({m.group()[:20]})")
            bonus += 3
    if status == "200":
        bonus += 1
    elif status in ("404", "500"):
        bonus -= 2
    finding["priority"] += bonus
    finding["confirmations"] = confirmations
    return finding


def parse(xml_path):
    root = ET.parse(xml_path).getroot()
    findings = []
    endpoint_counter = Counter()
    param_counter = Counter()
    value_index = defaultdict(list)   # 参数值->出现的item索引(倒排索引)
    all_items = []
    total = 0

    for idx, item in enumerate(root.findall("item"), start=1):
        total += 1
        url = item.findtext("url") or ""
        method = item.findtext("method") or ""
        status = item.findtext("status") or ""
        raw_req = decode(item.findtext("request"))
        raw_resp = decode(item.findtext("response"))
        body = split_body(raw_req)
        resp_body = split_body(raw_resp)
        haystack = (url + " " + body).lower()
        params = extract_params(url, body)

        all_items.append({
            "index": idx, "url": url, "method": method,
            "status": status, "xml_elem": item
        })
        endpoint_counter[normalize_path(url)] += 1
        for k, v in params:
            param_counter[k.lower()] += 1
            if v and len(v) >= 4:
                value_index[v].append(idx)

        for vuln_type, rule in RULES.items():
            hit = next((kw for kw in rule["keywords"] if kw in haystack), None)
            if not hit:
                continue
            if is_false_positive(vuln_type, method, params, hit):
                continue
            priority = rule["severity"] * rule["likelihood"]
            if method == "POST":
                priority += 2
            f = {
                "index": idx, "type": vuln_type, "method": method,
                "url": url, "status": status, "hit": hit,
                "severity": rule["severity"], "likelihood": rule["likelihood"],
                "priority": priority, "why": rule["why"],
                "params": params, "body": body, "confirmations": [],
            }
            f = enrich_with_response(f, resp_body, status)
            findings.append(f)

    dedup = {}
    for f in findings:
        key = (normalize_path(f["url"]), f["type"])
        if key not in dedup or f["priority"] > dedup[key]["priority"]:
            dedup[key] = f
    findings = sorted(dedup.values(), key=lambda x: x["priority"], reverse=True)
    return findings, endpoint_counter, param_counter, total, value_index, all_items


def find_related(finding, value_index):
    """
    找'参数值相同'的其他请求。
    ★ 学习提示：value_index是倒排索引(值→位置)，查关联O(1)，
      不用每次全表扫。倒排索引是搜索引擎核心数据结构。
    """
    related = set()
    shared = {}
    for k, v in finding["params"]:
        if v and len(v) >= 4 and v in value_index:
            others = [i for i in value_index[v] if i != finding["index"]]
            if others:
                related.update(others)
                shared[v] = (k, sorted(others))
    return sorted(related), shared


def export_xml(finding, related_idx, all_items, out_path):
    """[新功能3] 自身+关联请求导出为新xml，可被Burp重新导入"""
    target = set([finding["index"]] + list(related_idx))
    root = ET.Element("items")
    for it in all_items:
        if it["index"] in target:
            root.append(it["xml_elem"])
    ET.ElementTree(root).write(out_path, encoding="utf-8",
                               xml_declaration=True)
    return len(target)


def show_list(findings):
    print("\n" + "=" * 66)
    print("  高疑点列表（已过滤误报 + 响应增强，按优先级排序）")
    print("=" * 66)
    for i, f in enumerate(findings, start=1):
        p = max(0, min(f["priority"], 30))
        bar = "■" * p + "□" * (30 - p)
        flag = "  ★响应有敏感数据" if f["confirmations"] else ""
        print(f"[{i:>2}] 优先级{f['priority']:>2} {bar}{flag}")
        print(f"     {f['type']} | [{f['method']}] {f['url'][:62]}")
    print("-" * 66)


def show_detail(f, value_index, all_items):
    related_idx, shared = find_related(f, value_index)
    print("\n" + "=" * 66)
    print(f"  详情  |  {f['type']}")
    print("=" * 66)
    print(f"  xml位置   : 第 {f['index']} 条")
    print(f"  方法/状态 : {f['method']}  /  {f['status']}")
    print(f"  URL       : {f['url']}")
    print(f"  命中词    : {f['hit']}")
    print(f"  评分      : 威胁{f['severity']} 可能{f['likelihood']} 优先级{f['priority']}")
    print(f"  为什么    : {f['why']}")
    if f["confirmations"]:
        print(f"  ★响应确认 : {', '.join(f['confirmations'])}")
    print("-" * 66)
    print("  本请求关键参数：")
    for k, v in f["params"]:
        vv = (v[:46] + "...") if len(v) > 46 else (v or "(空)")
        print(f"    {k:<20} = {vv}")
    print("-" * 66)
    if related_idx:
        print(f"  ◆ 关联请求（共享相同参数值，xml第 {related_idx} 条）")
        for val, (pname, idxs) in shared.items():
            vv = (val[:38] + "...") if len(val) > 38 else val
            print(f"    {pname}={vv}  →  也出现在 xml第 {idxs} 条")
    else:
        print("  ◆ 无参数值相同的关联请求")
    print("-" * 66)
    print("  子操作：c=查看业务链  e=导出本组为xml  回车=返回")
    sub = input("  >>> ").strip().lower()
    if sub == "c":
        show_chain(f, related_idx, all_items)
        input("\n  按回车返回...")
    elif sub == "e":
        out = f"chain_{f['index']}.xml"
        n = export_xml(f, related_idx, all_items, out)
        print(f"  [+] 已导出 {n} 条请求到 {out}（可Burp Project→Import导入）")
        input("\n  按回车返回...")


def show_chain(f, related_idx, all_items):
    """[新功能2] 业务链：自身+关联按xml顺序排"""
    chain = sorted(set([f["index"]] + list(related_idx)))
    print("\n" + "=" * 66)
    print(f"  业务链视图（{len(chain)} 个请求，按调用顺序）")
    print("=" * 66)
    for idx in chain:
        it = next(x for x in all_items if x["index"] == idx)
        mark = "  ←当前" if idx == f["index"] else ""
        print(f"  [xml第{idx:>3}条] [{it['method']:>6}] {it['status']:>3} "
              f"{normalize_path(it['url'])}{mark}")
    print("=" * 66)
    print("  ★ 回Burp定位：按上面 方法+路径 在HTTP history搜索框过滤")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 analyzer_tui.py burp.xml")
        sys.exit(1)
    try:
        findings, ep, pm, total, value_index, all_items = parse(sys.argv[1])
    except ET.ParseError as e:
        print(f"[!] XML解析失败: {e}")
        sys.exit(1)

    print(f"\n[*] 共 {total} 条请求，过滤后 {len(findings)} 个高疑点")
    while True:
        show_list(findings)
        print("操作：编号=详情  q=退出")
        c = input(">>> ").strip().lower()
        if c == "q":
            break
        elif c.isdigit() and 1 <= int(c) <= len(findings):
            show_detail(findings[int(c) - 1], value_index, all_items)
        else:
            print("无效输入。")


if __name__ == "__main__":
    main()

# ============================================================
# 后期扩展（写给你自己）：
#   1. is_false_positive 现在简单，针对每种漏洞写更细的上下文
#      规则——降噪的关键，值得持续打磨。
#   2. RESP_PATTERNS 可加业务层信号：本不该success却success、
#      响应里出现非本人用户名等。
#   3. 业务链现在靠"参数值相同"串联，更准的是结合item的time
#      字段按时序排，能还原真实操作流程。
#   4. 导出的xml可被Burp重新导入(Project→Import)，形成
#      "分析→筛选→回灌Burp精测"的闭环。
#   深入方向：把 RULES 和 RESP_PATTERNS 抽到外部yaml，脚本
#   只做引擎——这是nuclei的设计思想，学会能看懂nuclei。
# ============================================================
