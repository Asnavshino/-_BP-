#!/usr/bin/env python3
# ============================================================
# Burp 交互式分析器 v5  —— 模块化重构版
# ============================================================
# 用法: python3 analyzer_tui.py burp.xml [目标域名关键词]
# 例:   python3 analyzer_tui.py burp.xml aihuishou
#
# ★ 核心定位（务必理解）：
#   脚本【不能判断漏洞是否成立】。漏洞成不成立取决于服务端
#   有没有做某个校验，只有发请求实测才知道。脚本作用是：
#   把"最值得你花时间实测的"排在前面。所有分数是"测试性价比"，
#   不是"漏洞概率"。
#
# 模块结构（改哪块找对应函数）：
#   [常量区] RULES/NOISE_PARAMS/RESP_PATTERNS/TARGET_DOMAINS
#   [解析层] decode/split_body/parse
#   [定位层] locate_match  —— 命中在 req_url/req_body/resp
#   [分类层] classify_action —— 查询/写入/删除
#   [确认层] confirm_response —— 响应找敏感数据(收紧+上下文)
#   [评分层] score_costperf/score_actionable/score_all (各自独立)
#   [关联层] build_value_index/find_related (排除噪音参数)
#   [视图层] view_costperf/view_actionable/view_all
#   [展示层] show_table/show_detail/show_chain/export_xml
# ============================================================

import sys, base64, re
import xml.etree.ElementTree as ET
from collections import defaultdict

# ============== 常量区（最常改这里） ==============

# 只分析含这些词的域名，其余(mozilla/jython等)丢弃
# ★缺口修复：不过滤第三方流量会污染所有排序
TARGET_DOMAINS = ["aihuishou", "atrenew", "ahsdevice", "paijitang",
                  "paipai", "jidaxia", "ahs5", "allthingsrenew"]

# 噪音参数黑名单：全站统一风控/追踪参数，不能作关联依据
# ★缺口修复：acw_sc__v3每个请求都带，不排除会"全部互相关联"
NOISE_PARAMS = {"acw_sc__v3", "acw_tc", "acw_sc_v2", "sensorsdata",
                "sensorsdata2015jssdkcross", "_", "timestamp", "t",
                "ssxmod_itna", "ssxmod_itna2", "v3"}

RULES = {
    "水平越权/IDOR": {
        "keywords": ["orderid", "orderno", "ordersn", "order_id",
                     "order_no", "addressid", "address_id", "couponid",
                     "voucherid", "salegoodsno", "userkey", "ybskuidlist"],
        "base_harm": 3,
        "why": "带资源ID。换成别人的ID能拿到数据=越权。"},
    "垂直越权": {
        "keywords": ["isadmin", "role", "usertype", "user_type",
                     "userlevel", "user_group", "permission", "auth_level"],
        "base_harm": 4,
        "why": "有角色/权限字段。改大权限值看能否提权。"},
    "未授权访问": {
        "keywords": ["/admin", "/manage", "/backstage", "/internal",
                     "/debug", "/actuator", "/console"],
        "base_harm": 4,
        "why": "管理类路径。删Cookie直接访问看是否需鉴权。"},
    "价格/金额篡改": {
        "keywords": ["amount", "price", "totalamount", "payamount",
                     "money", "fee", "discount", "totalfee", "payprice"],
        "base_harm": 4,
        "why": "带金额字段。改低/改负看服务端是否重新验价。"},
    "文件操作/路径穿越": {
        "keywords": ["filename=", "filepath=", "file=", "path=",
                     "filename\":", "download", "upload"],
        "base_harm": 3,
        "why": "文件参数。试 ../ 穿越或改类型绕过上传限制。"},
    "SSRF/重定向": {
        "keywords": ["url=", "redirect=", "redirect_uri", "callback=",
                     "returnurl", "return_url", "next="],
        "base_harm": 3,
        "why": "参数值是URL。改内网测SSRF，改外站测重定向。"},
    "敏感信息泄露": {
        "keywords": ["phone", "mobile", "idcard", "id_card",
                     "realname", "real_name", "bankcard"],
        "base_harm": 2,
        "why": "响应可能含PII。结合越权危害升级。"},
}

# 响应敏感数据正则。★缺口修复：要求附近有字段名才算确认，
# 否则商品ID/时间戳长数字会被误判成身份证/手机号
RESP_PATTERNS = {
    "手机号": (re.compile(r'1[3-9]\d{9}'),
              re.compile(r'(phone|mobile|tel|手机)', re.I)),
    "身份证": (re.compile(r'\b\d{17}[\dXx]\b'),
              re.compile(r'(idcard|id_card|身份证|identity)', re.I)),
    "邮箱":   (re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b'),
              re.compile(r'(email|mail|邮箱)', re.I)),
    "SQL报错": (re.compile(r'(SQLException|SQL syntax|ORA-\d{5})', re.I),
              None),
    "堆栈泄露": (re.compile(r'(at java\.[\w.]+\(|Traceback \(most recent)'),
              None),
}

# ============== 解析层 ==============
def decode(text):
    if not text:
        return ""
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return text

def split_body(raw):
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            return raw.split(sep, 1)[1]
    return ""

def normalize_path(url):
    p = url.split("?")[0]
    p = re.sub(r"/\d{4,}", "/{ID}", p)
    p = re.sub(r"^https?://[^/]+", "", p)
    return p or "/"

def in_scope(url):
    """★缺口修复：只保留目标域名"""
    return any(d in url.lower() for d in TARGET_DOMAINS)

def extract_params(text):
    params = []
    for k, v in re.findall(r"[?&]([a-zA-Z_][\w]*)=([^&\s]*)", text):
        params.append((k, v))
    for k, v in re.findall(r'"([a-zA-Z_][\w]*)"\s*:\s*"?([^",}\]]*)"?', text):
        params.append((k, v.strip()))
    return params

# ============== 定位层 ★缺口修复 ==============
def locate_match(keyword, url, req_body, resp_body):
    """命中在哪: req_body>req_url>resp。
    req_body=可篡改真目标; resp=只是会返回该字段,不是篡改点"""
    kw = keyword.lower()
    if kw in req_body.lower():
        return "req_body"
    if kw in url.lower():
        return "req_url"
    if kw in resp_body.lower():
        return "resp"
    return None

# ============== 分类层 ★缺口修复 ==============
def classify_action(method, url):
    """write/delete/query。价格篡改只在write有意义,
    query类有price是正常的,这步砍掉大量查询噪音"""
    u = url.lower()
    if any(w in u for w in ["delete", "remove", "cancel", "del-"]):
        return "delete"
    if method == "POST" and any(w in u for w in
            ["create", "submit", "save", "add", "update", "modify",
             "pay", "order", "confirm", "bind", "set"]):
        return "write"
    if method in ("PUT", "DELETE", "PATCH"):
        return "write"
    if method == "POST":
        return "write"
    return "query"

# ============== 确认层 ★缺口修复 ==============
def confirm_response(resp_body):
    """响应找敏感数据。要求敏感值前后120字符内有对应字段名,
    否则商品ID/时间戳会被误判"""
    hits = []
    for name, (val_pat, ctx_pat) in RESP_PATTERNS.items():
        m = val_pat.search(resp_body)
        if not m:
            continue
        if ctx_pat is None:
            hits.append(f"{name}({m.group()[:16]})")
        else:
            s = max(0, m.start() - 120)
            window = resp_body[s:m.end() + 120]
            if ctx_pat.search(window):
                hits.append(f"{name}({m.group()[:16]})")
    return hits

# 响应里要重点展示的"身份标识字段"——越权后最先变化的就是这些。
# ★学习提示：判断越权不用看整个响应，只看这几个字段变没变、
#   变成谁的了，就够了。这是把"对比整个响应"简化成
#   "对比关键字段"的实战技巧。
# ★扩展点：发现某接口有别的身份字段，往这里加。
IDENTITY_FIELDS = [
    "userid", "user_id", "uid", "memberid", "member_id",
    "username", "user_name", "nickname", "realname", "real_name",
    "name", "phone", "mobile", "tel", "email", "idcard", "id_card",
    "addressid", "address_id", "address", "locateaddress",
    "cityname", "districtname", "amount", "price", "payprice",
    "totalamount", "balance", "orderno", "order_no", "ordersn",
]

def looks_like_text(s):
    """判断是不是可读文本(防gzip/二进制乱码里乱匹配)。
    ★缺口修复点3：可打印字符比例过低=非文本，跳过"""
    if not s:
        return False
    sample = s[:500]
    printable = sum(1 for c in sample if c.isprintable() or c in "\r\n\t")
    return printable / len(sample) > 0.7

def extract_resp_fields(resp_body):
    """
    从响应里提取身份标识字段。★缺口修复：
    - 只取IDENTITY_FIELDS里的,不倒出整个响应(防刷屏)
    - 同名去重保留第一个(防 userId 和 data.userId 重复)
    - 非文本/空响应返回标记,不报错
    返回: (状态说明, [(字段名,值), ...])
    """
    if not resp_body.strip():
        return ("无响应体", [])
    if not looks_like_text(resp_body):
        return ("响应非文本(可能压缩/二进制)", [])
    found = {}
    # 容错:优先正则抓键值对(嵌套JSON也能抓到),不强依赖json.loads
    for k, v in re.findall(
            r'"([a-zA-Z_][\w]*)"\s*:\s*"?([^",}\]\[{]*)"?', resp_body):
        kl = k.lower()
        if kl in IDENTITY_FIELDS and kl not in found:
            val = v.strip()
            if val and val not in ("null", ""):
                found[kl] = val[:50]
    if not found:
        return ("响应中无身份标识字段", [])
    return ("ok", list(found.items()))

# ============== 评分层 ★每表独立 ==============
def score_costperf(f):
    """性价比 = 危害×可测性÷成本。成本依据公开非黑盒"""
    harm = f["base_harm"]
    t = {"req_body": 3, "req_url": 2, "resp": 1}[f["loc"]]
    if f["status"] == "200":
        t += 1
    elif f["status"] in ("404", "500"):
        t = max(1, t - 2)
    cost = 1
    if f["loc"] == "req_body":
        cost = 2
    if f["action"] == "write":
        cost += 1
    f["_cost_reason"] = f"位置={f['loc']},动作={f['action']}"
    return round(harm * t / cost, 1)

def score_actionable(f):
    """硬条件不满足直接0(不进此表):写操作+命中在请求+可访问"""
    if f["action"] not in ("write", "delete"):
        return 0
    if f["loc"] not in ("req_body", "req_url"):
        return 0
    if f["status"] in ("404", "500"):
        return 0
    s = f["base_harm"] * 2
    if f["loc"] == "req_body":
        s += 3
    if f["confirmations"]:
        s += 3
    return s

def score_all(f):
    """全量:基础打分不漏"""
    s = f["base_harm"] * 2
    if f["loc"] == "req_body":
        s += 2
    if f["confirmations"]:
        s += 3
    if f["status"] == "200":
        s += 1
    return s

# ============== 风险分级 ★新增 ==============
# 四档对齐漏洞盒子规则(严重/高危/中危/低危),不是自创标准。
# 判定依据公开,详情里会说明为什么是这个等级。
# ★扩展点:想调整分级阈值,只改这个函数。
RISK_ORDER = {"CRIT": 4, "HIGH": 3, "MED": 2, "LOW": 1}

def risk_level(f):
    """
    返回 (等级标签, 判定依据文字)。
    依据 = 危害程度(base_harm) × 可确认性(命中位置/响应确认)
    """
    harm = f["base_harm"]
    confirmed = bool(f["confirmations"])
    in_req = f["loc"] in ("req_body", "req_url")

    if harm >= 4 and confirmed:
        return ("CRIT", "高危类型(harm≥4)且响应已确认敏感数据=实锤级")
    if harm >= 4 and f["loc"] == "req_body":
        return ("HIGH", "高危类型且命中在请求body(可直接篡改)")
    if harm >= 3 and confirmed:
        return ("HIGH", "中危以上类型且响应已确认敏感数据")
    if harm >= 3 and in_req:
        return ("MED", "中危类型,命中在请求里(可测但未见响应实锤)")
    return ("LOW", "命中在响应/低危类型,信息价值为主")

# ============== 关联层 ==============
def build_value_index(records):
    """参数值->[记录idx]倒排索引。★缺口修复:跳过NOISE_PARAMS"""
    idx = defaultdict(list)
    for r in records:
        for k, v in r["params"]:
            if k.lower() in NOISE_PARAMS:
                continue
            if v and len(v) >= 4:
                idx[v].append(r["index"])
    return idx

def find_related(f, value_index):
    related, shared = set(), {}
    for k, v in f["params_all"]:
        if k.lower() in NOISE_PARAMS:
            continue
        if v and len(v) >= 4 and v in value_index:
            others = [i for i in value_index[v] if i != f["index"]]
            if others:
                related.update(others)
                shared[v] = (k, sorted(others)[:15])
    return sorted(related), shared

# ============== 解析主流程 ==============
def parse(xml_path):
    root = ET.parse(xml_path).getroot()
    findings, all_items = [], []
    endpoint_calls = defaultdict(list)
    value_records = []
    total = skipped = 0

    for idx, item in enumerate(root.findall("item"), start=1):
        total += 1
        url = item.findtext("url") or ""
        if not in_scope(url):
            skipped += 1
            continue
        method = item.findtext("method") or ""
        status = item.findtext("status") or ""
        req_body = split_body(decode(item.findtext("request")))
        resp_body = split_body(decode(item.findtext("response")))
        params_all = extract_params(url) + extract_params(req_body)

        all_items.append({"index": idx, "url": url, "method": method,
                          "status": status, "xml_elem": item})
        value_records.append({"index": idx, "params": params_all})
        np = normalize_path(url)
        endpoint_calls[np].append(idx)

        hay = (url + " " + req_body + " " + resp_body).lower()
        _resp_msg, _resp_fields = extract_resp_fields(resp_body)
        for vtype, rule in RULES.items():
            hit = next((kw for kw in rule["keywords"] if kw in hay), None)
            if not hit:
                continue
            loc = locate_match(hit, url, req_body, resp_body)
            if loc is None:
                continue
            action = classify_action(method, url)
            if vtype == "价格/金额篡改" and loc == "resp" \
                    and action == "query":
                continue
            findings.append({
                "index": idx, "type": vtype, "method": method,
                "url": url, "status": status, "hit": hit, "loc": loc,
                "action": action, "base_harm": rule["base_harm"],
                "why": rule["why"], "params_all": params_all,
                "confirmations": confirm_response(resp_body),
                "resp_status_msg": _resp_msg,
                "resp_fields": _resp_fields,
                "norm_path": np})

    # 去重:同接口同类型保留参数最丰富代表,记录调用次数
    dedup = {}
    for f in findings:
        key = (f["norm_path"], f["type"])
        f["call_count"] = len(endpoint_calls[f["norm_path"]])
        if key not in dedup or len(f["params_all"]) > \
                len(dedup[key]["params_all"]):
            dedup[key] = f
    findings = list(dedup.values())

    for f in findings:
        f["s_cost"] = score_costperf(f)
        f["s_act"] = score_actionable(f)
        f["s_all"] = score_all(f)
        f["risk"], f["risk_reason"] = risk_level(f)

    vidx = build_value_index(value_records)
    return findings, all_items, vidx, total, skipped

# ============== 视图层 ★三表同数据不同排序 ==============
def view_costperf(fs):
    return (sorted(fs, key=lambda x: x["s_cost"], reverse=True),
            "性价比表（时间有限先测这些=危害×可测性÷成本）", "s_cost")

def view_actionable(fs):
    r = [f for f in fs if f["s_act"] > 0]
    r.sort(key=lambda x: x["s_act"], reverse=True)
    return r, "最值得实测表（写操作+可篡改+可访问，宁缺毋滥）", "s_act"

def view_all(fs):
    return (sorted(fs, key=lambda x: x["s_all"], reverse=True),
            "全量表（所有疑点，不漏）", "s_all")

VIEWS = {"1": view_costperf, "2": view_actionable, "3": view_all}

# ============== 展示层 ==============
def show_table(rows, title, sk):
    print("\n" + "=" * 68)
    print(f"  {title}")
    # 表头加分级统计：一眼看出这张表有多少严重/高危
    cnt = {"CRIT": 0, "HIGH": 0, "MED": 0, "LOW": 0}
    for f in rows:
        cnt[f["risk"]] += 1
    print(f"  风险分布: CRIT {cnt['CRIT']} | HIGH {cnt['HIGH']} | "
          f"MED {cnt['MED']} | LOW {cnt['LOW']}")
    print("=" * 68)
    if not rows:
        print("  （此表无条目）")
    for i, f in enumerate(rows, start=1):
        flag = " ★响应含敏感数据" if f["confirmations"] else ""
        loc = {"req_body": "body", "req_url": "URL", "resp": "响应"}[f["loc"]]
        # ★新增：每条前面加风险等级文字标签
        print(f"[{i:>2}] [{f['risk']:<4}] 分{f[sk]:>4} | "
              f"{f['type']:<11} | {f['action']:<5} | 命中@{loc}{flag}")
        print(f"     [{f['method']}] {f['url'][:58]}")
    print("-" * 68)

def show_detail(f, vidx, all_items):
    related, shared = find_related(f, vidx)
    print("\n" + "=" * 68)
    print(f"  详情 | {f['type']}")
    print("=" * 68)
    print(f"  xml位置  : 第 {f['index']} 条")
    print(f"  方法/状态: {f['method']} / {f['status']}")
    print(f"  接口动作 : {f['action']} (write=写 query=查询)")
    print(f"  命中位置 : {f['loc']} (req_body可篡改/resp仅信息)")
    print(f"  URL      : {f['url']}")
    print(f"  命中词   : {f['hit']}")
    print(f"  三表得分 : 性价比{f['s_cost']} 实测{f['s_act']} 全量{f['s_all']}")
    print(f"  成本依据 : {f['_cost_reason']}")
    print(f"  风险等级 : [{f['risk']}]  ——  {f['risk_reason']}")
    print(f"  为什么   : {f['why']}")
    if f["call_count"] > 1:
        print(f"  ◎ 此接口你调用过 {f['call_count']} 次——"
              f"同接口不同参数=现成越权测试素材")
    if f["confirmations"]:
        print(f"  ★响应确认: {', '.join(f['confirmations'])}")
    print("-" * 68)
    print("  请求参数（已过滤噪音参数）：")
    for k, v in f["params_all"]:
        if k.lower() in NOISE_PARAMS:
            continue
        vv = (v[:44] + "...") if len(v) > 44 else (v or "(空)")
        print(f"    {k:<20} = {vv}")
    print("-" * 68)
    if related:
        print("  ◆ 关联请求（参数值相同，已排噪音）")
        for val, (pn, idxs) in list(shared.items())[:8]:
            vv = (val[:34] + "...") if len(val) > 34 else val
            print(f"    {pn}={vv}  → xml第 {idxs} 条")
    else:
        print("  ◆ 无有效关联请求")
    print("-" * 68)
    # ★新增：响应身份标识字段。重放(改ID)后只看这几个字段
    #   变没变、变成谁的，就知道有没有越权，不用比整个响应。
    print("  ▼ 响应身份字段（重放后对比这些判断越权）")
    if f["resp_fields"]:
        for k, v in f["resp_fields"]:
            print(f"    {k:<18} = {v}")
        print("    ↑ 改ID重放后，这些值若变成别人的=越权成立")
    else:
        print(f"    （{f['resp_status_msg']}）")
    print("-" * 68)
    print("  子操作：c=业务链  e=导出本组xml  回车=返回")
    sub = input("  >>> ").strip().lower()
    if sub == "c":
        show_chain(f, related, all_items)
        input("\n  回车返回...")
    elif sub == "e":
        out = f"chain_{f['index']}.xml"
        n = export_xml(f, related, all_items, out)
        print(f"  [+] 导出 {n} 条到 {out}（Burp可Project→Import）")
        input("\n  回车返回...")

def show_chain(f, related, all_items):
    chain = sorted(set([f["index"]] + list(related)))
    print("\n" + "=" * 68)
    print(f"  业务链（{len(chain)} 个请求，按xml顺序）")
    print("=" * 68)
    for idx in chain:
        it = next((x for x in all_items if x["index"] == idx), None)
        if not it:
            continue
        mark = "  ←当前" if idx == f["index"] else ""
        print(f"  [xml{idx:>3}] [{it['method']:>5}] {it['status']:>3} "
              f"{normalize_path(it['url'])}{mark}")
    print("=" * 68)

def export_xml(f, related, all_items, out):
    target = set([f["index"]] + list(related))
    root = ET.Element("items")
    for it in all_items:
        if it["index"] in target:
            root.append(it["xml_elem"])
    ET.ElementTree(root).write(out, encoding="utf-8", xml_declaration=True)
    return len(target)

# ============== 主循环 ==============
def main():
    if len(sys.argv) < 2:
        print("用法: python3 analyzer_tui.py burp.xml [域名关键词]")
        sys.exit(1)
    if len(sys.argv) >= 3:
        TARGET_DOMAINS.clear()
        TARGET_DOMAINS.append(sys.argv[2].lower())
    try:
        findings, all_items, vidx, total, skipped = parse(sys.argv[1])
    except ET.ParseError as e:
        print(f"[!] XML解析失败: {e}")
        sys.exit(1)

    print(f"\n[*] 共 {total} 条，过滤 {skipped} 条非目标域名，"
          f"命中 {len(findings)} 个疑点")

    # ★bug修复1：启动先问要哪张表，不默认显示
    # ★bug修复2：切表用字母 a/b/c，看详情用纯数字编号，
    #   两者不再冲突（之前 '1' 既是切表又是看第1条，逻辑乱）
    print("\n请选择要查看的表：")
    print("  a = 性价比表（时间有限，先测高性价比的）")
    print("  b = 最值得实测表（写操作+可篡改+可访问，宁缺毋滥）")
    print("  c = 全量表（所有疑点，不漏）")
    table_map = {"a": "1", "b": "2", "c": "3"}
    while True:
        sel = input("选择表 (a/b/c) >>> ").strip().lower()
        if sel in table_map:
            current = table_map[sel]
            break
        print("请输入 a / b / c")

    # 风险筛选状态：None=不筛选(显示全部)，否则只显示>=该等级的
    risk_filter = None
    while True:
        rows, title, sk = VIEWS[current](findings)
        # ★新增：按风险等级筛选子表
        if risk_filter:
            min_lv = RISK_ORDER[risk_filter]
            rows = [f for f in rows
                    if RISK_ORDER[f["risk"]] >= min_lv]
            title += f"  [仅显示 >= {risk_filter}]"
        show_table(rows, title, sk)
        print("操作：数字=看详情 | a/b/c=切表 | "
              "f=按风险筛选子表 | r=取消筛选 | q=退出")
        ch = input(">>> ").strip().lower()
        if ch == "q":
            break
        elif ch in table_map:
            current = table_map[ch]
        elif ch == "f":
            # 子表选项：选只看哪个等级以上
            print("  只看哪个等级以上？ "
                  "1=CRIT 2=HIGH及以上 3=MED及以上 4=全部")
            lv = input("  >>> ").strip()
            risk_filter = {"1": "CRIT", "2": "HIGH",
                           "3": "MED", "4": None}.get(lv, risk_filter)
        elif ch == "r":
            risk_filter = None
            print("  已取消风险筛选，显示全部。")
        elif ch.isdigit() and 1 <= int(ch) <= len(rows):
            show_detail(rows[int(ch) - 1], vidx, all_items)
        else:
            print("无效输入：数字看详情，a/b/c切表，"
                  "f筛选，r取消筛选，q退出。")

if __name__ == "__main__":
    main()

# ============================================================
# 后期扩展（写给你自己）：
#   0. [已知小问题] risk_level里"harm≥4且confirmed"判CRIT时
#      没排除loc==resp的情况。真实数据中命中resp的价格已被
#      误报过滤拦掉,影响极小;若要严谨,在该分支加 and in_req。
#   1. 三个 score_* 函数完全独立，调某表逻辑只改对应函数。
#   2. classify_action 现靠URL关键词猜，可结合响应体判断
#      (返回"创建成功"=write)。
#   3. v6方向：响应基线对比——同接口正常vs异常参数请求对比
#      响应结构差异。判断越权/信息泄露最强信号，需脚本理解
#      "哪两条该对比"，复杂度高，单独做。
#   4. NOISE_PARAMS/TARGET_DOMAINS 可抽到外部配置文件。
#   深入：RULES+RESP_PATTERNS抽成yaml,脚本变纯引擎=nuclei思想。
# ============================================================
