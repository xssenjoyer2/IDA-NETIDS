#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, time, os, json
from pathlib import Path
import numpy as np
import pandas as pd

# -------------------------
# Helpers / Config loading
# -------------------------

FAIL_STATES  = {"S0","S1","SH","REJ","RSTO","RSTR","RSTOS0"}
SUCCESS_ST   = {"SF","S1","ESTAB"}

def now_ts() -> float:
    return time.time()

def load_json(rules_dir: Path, name: str, default: dict) -> dict:
    p = rules_dir / f"{name}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return default

def read_window(scores_csv: Path, window_sec: int, max_rows: int) -> pd.DataFrame:
    if not scores_csv.exists():
        return pd.DataFrame()
    df = pd.read_csv(scores_csv, low_memory=False)
    # filtre: pencere
    tcut = now_ts() - window_sec
    if "ts" in df.columns:
        df = df[pd.to_numeric(df["ts"], errors="coerce").fillna(0) >= tcut]
    # kuyruğu sınırla
    if len(df) > max_rows:
        df = df.iloc[-max_rows:]
    return df.reset_index(drop=True)

def ensure_cols(df: pd.DataFrame) -> pd.DataFrame:
    """Bizim stream sütunlarını normalize et, eksikleri doldur."""
    df = df.copy()

    # bizim isimler → Zeek'e yakın eşle
    ren = {"orig_h":"id.orig_h","orig_p":"id.orig_p",
           "resp_h":"id.resp_h","resp_p":"id.resp_p"}
    for a,b in ren.items():
        if b not in df.columns and a in df.columns:
            df[b] = df[a]

    # türler
    for c in ("id.orig_p","id.resp_p","orig_pkts","resp_pkts","missed_bytes"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    for c in ("duration","orig_bytes","resp_bytes","p_cal","margin"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(float)

    for c in ("id.orig_h","id.resp_h","proto","service","conn_state","history"):
        if c in df.columns:
            df[c] = df[c].astype(str)
        else:
            df[c] = "-"

    # syn_noack: history yoksa 0, varsa S var & H/h yok → 1.0
    if "syn_noack" not in df.columns:
        h = df["history"]
        df["syn_noack"] = ((h.str.contains("S")) & (~h.str.contains("H", case=False))).astype(float)

    # yardımcı anahtarlar
    df["_pair_resp_hp"] = df["id.resp_h"].astype(str) + "|" + df["id.resp_p"].astype(str)
    df["_pair_orig_hp"] = df["id.orig_h"].astype(str) + "|" + df["id.resp_p"].astype(str)

    # ts float
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0).astype(float)

    return df

def time_bin(ts: pd.Series, w: int) -> pd.Series:
    t = pd.to_numeric(ts, errors="coerce").fillna(0.0)
    return (t // w).astype(int) * w

def append_csv(path: Path, df: pd.DataFrame):
    path.parent.mkdir(parents=True, exist_ok=True)
    hdr = not path.exists()
    df.to_csv(path, mode="a", index=False, header=hdr)

# -------------------------
# Rule blocks
# -------------------------

def detect_portscan(df: pd.DataFrame, scan_cfg: dict, short: int, long: int) -> pd.DataFrame:
    if df.empty: return pd.DataFrame()

    ws = int(scan_cfg.get("short_window_seconds", short))
    wl = int(scan_cfg.get("long_window_seconds", long))
    s0_th   = float(scan_cfg.get("s0_ratio_threshold", 0.5))
    syn_th  = float(scan_cfg.get("syn_noack_threshold", 0.5))
    h_dst_s = int(scan_cfg.get("unique_dst_threshold_short", 12))
    h_dst_l = int(scan_cfg.get("unique_dst_threshold_long",  60))
    v_prt_s = int(scan_cfg.get("unique_port_threshold_short", 15))
    v_prt_l = int(scan_cfg.get("unique_port_threshold_long",  80))
    pair_s  = int(scan_cfg.get("pair_threshold_short",       20))
    pair_l  = int(scan_cfg.get("pair_threshold_long",       120))
    burst_s = int(scan_cfg.get("burst_conn_threshold_short", 300))
    victim_src_s = int(scan_cfg.get("victim_unique_src_threshold_short", 25))
    victim_src_l = int(scan_cfg.get("victim_unique_src_threshold_long",  80))

    tcp = df[df["proto"].str.lower()=="tcp"].copy()
    if tcp.empty: return pd.DataFrame()

    tcp["wS"] = time_bin(tcp["ts"], ws)
    tcp["wL"] = time_bin(tcp["ts"], wl)

    # kaynak merkezli
    gS = tcp.groupby(["id.orig_h","wS"], sort=False)
    gL = tcp.groupby(["id.orig_h","wL"], sort=False)

    s_rows  = gS["ts"].transform("size").clip(lower=1)
    s_dst   = gS["id.resp_h"].transform("nunique")
    s_port  = gS["id.resp_p"].transform("nunique")
    s_pair  = gS["_pair_resp_hp"].transform("nunique")
    s_s0    = gS["conn_state"].transform(lambda s: s.isin(FAIL_STATES).sum())/s_rows
    s_synm  = gS["syn_noack"].transform("mean")

    l_dst   = gL["id.resp_h"].transform("nunique")
    l_port  = gL["id.resp_p"].transform("nunique")
    l_pair  = gL["_pair_resp_hp"].transform("nunique")

    # kurban tarafı (distributed scan’ler)
    gvS = tcp.groupby(["id.resp_h","wS"], sort=False)
    v_usrc_s = gvS["id.orig_h"].transform("nunique")
    gvL = tcp.groupby(["id.resp_h","wL"], sort=False)
    v_usrc_l = gvL["id.orig_h"].transform("nunique")

    hit = (
        (s_dst >= h_dst_s) |
        (s_port >= v_prt_s) |
        (s_pair >= pair_s) |
        (l_dst >= h_dst_l) |
        (l_port >= v_prt_l) |
        (l_pair >= pair_l) |
        (s_rows >= burst_s) |
        (s_s0 >= s0_th)     |
        (s_synm >= syn_th)  |
        (v_usrc_s >= victim_src_s) |
        (v_usrc_l >= victim_src_l)
    )

    cand = tcp[hit].copy()
    if cand.empty: return pd.DataFrame()

    agg = cand.groupby("id.orig_h").agg(
        total=("ts","size"),
        uniq_hosts=("id.resp_h","nunique"),
        uniq_ports=("id.resp_p","nunique"),
        fail_ratio=("conn_state", lambda s: float((s.isin(FAIL_STATES)).mean()))
    ).reset_index()
    agg["type"] = "port_scan"
    agg["severity"] = np.where( (agg["uniq_hosts"]>=h_dst_l) | (agg["uniq_ports"]>=v_prt_l), "high",
                        np.where( (agg["uniq_hosts"]>=h_dst_s) | (agg["uniq_ports"]>=v_prt_s), "med","low"))
    return agg.rename(columns={"id.orig_h":"attacker_ip"})

def detect_bruteforce(df: pd.DataFrame, brute_cfg: dict, short: int, long: int) -> pd.DataFrame:
    if df.empty: return pd.DataFrame()

    ws = int(brute_cfg.get("short_window_seconds", max(60, short)))
    wl = int(brute_cfg.get("slow_window_seconds",  max(600,long)))

    ports_focus   = set(brute_cfg.get("ports_focus", [22,21,23,25,110,143,445,3389,5900,3306,5432,8080,8443]))
    services_focus= set(x.lower() for x in brute_cfg.get("services_focus", ["ssh","ftp","telnet","smtp","imap","pop3","smb","rdp","vnc","http","ssl","https"]))
    exclude_ports = set(brute_cfg.get("exclude_ports", []))

    th_src     = int(brute_cfg.get("per_src_attempt_threshold", 40))
    th_srcdst  = int(brute_cfg.get("per_srcdst_attempt_threshold", 15))
    th_srcdstp = int(brute_cfg.get("per_srcdstport_attempt_threshold", 10))
    th_dst_msrc= int(brute_cfg.get("per_dst_multi_src_threshold", 30))
    th_fail    = float(brute_cfg.get("fail_ratio_threshold", 0.7))
    th_synm    = float(brute_cfg.get("syn_noack_mean_threshold", 0.35))
    th_slow    = int(brute_cfg.get("slow_attempt_threshold", 120))
    th_succbrk = int(brute_cfg.get("success_break_threshold", 1))
    req_focus  = bool(brute_cfg.get("require_focus_for_trigger", True))
    off_mult   = float(brute_cfg.get("off_focus_multiplier", 3.0))

    tcp = df[df["proto"].str.lower()=="tcp"].copy()
    if tcp.empty: return pd.DataFrame()
    tcp["wS"] = time_bin(tcp["ts"], ws)
    tcp["wL"] = time_bin(tcp["ts"], wl)

    focus_port = tcp["id.resp_p"].isin(ports_focus)
    focus_svc  = tcp["service"].str.lower().isin(services_focus)
    focus_gate = (focus_port | focus_svc) & (~tcp["id.resp_p"].isin(exclude_ports))

    gS   = tcp.groupby(["id.orig_h","wS"], sort=False)
    rows = gS["ts"].transform("size").astype(int)
    fails= gS["conn_state"].transform(lambda s: int(s.isin(FAIL_STATES).sum()))
    succ = gS["conn_state"].transform(lambda s: int(s.isin(SUCCESS_ST).sum()))
    synm = gS["syn_noack"].transform("mean")
    fail_ratio = np.where(rows>0, fails/rows, 0.0)

    gSD   = tcp.groupby(["id.orig_h","id.resp_h","wS"], sort=False)
    rows_sd = gSD["ts"].transform("size").astype(int)
    gSDP  = tcp.groupby(["id.orig_h","id.resp_h","id.resp_p","wS"], sort=False)
    rows_sdp= gSDP["ts"].transform("size").astype(int)

    gVD = tcp.groupby(["id.resp_h","wS"], sort=False)
    dst_msrc = gVD["id.orig_h"].transform("nunique")

    gL   = tcp.groupby(["id.orig_h","wL"], sort=False)
    rowsL= gL["ts"].transform("size").astype(int)
    failsL = gL["conn_state"].transform(lambda s: int(s.isin(FAIL_STATES).sum()))
    fail_ratioL = np.where(rowsL>0, failsL/rowsL, 0.0)

    # odak dışı ise eşik sertleştir
    eff_src     = np.where(focus_gate, th_src,    int(th_src*off_mult))
    eff_srcdst  = np.where(focus_gate, th_srcdst, int(th_srcdst*off_mult))
    eff_srcdstp = np.where(focus_gate, th_srcdstp,int(th_srcdstp*off_mult))
    eff_fail    = np.where(focus_gate, th_fail,   th_fail*1.5)

    brk = (succ >= th_succbrk)
    hit = (
        ((rows >= eff_src) | (rows_sd >= eff_srcdst) | (rows_sdp >= eff_srcdstp)) |
        (fail_ratio >= eff_fail) |
        (synm >= th_synm) |
        (dst_msrc >= th_dst_msrc) |
        ((rowsL >= th_slow) & (fail_ratioL >= eff_fail))
    ) & (~brk)

    if req_focus:
        hit = hit & focus_gate

    cand = tcp[hit].copy()
    if cand.empty: return pd.DataFrame()

    agg = cand.groupby(["id.orig_h","id.resp_h"]).agg(
        attempts=("ts","size"),
        uniq_ports=("id.resp_p","nunique"),
        fail_ratio=("conn_state", lambda s: float((s.isin(FAIL_STATES)).mean()))
    ).reset_index()
    agg["type"] = "bruteforce"
    agg["severity"] = np.where( (agg["attempts"]>=th_slow) | (agg["fail_ratio"]>=0.9), "high",
                         np.where( agg["attempts"]>=th_srcdst, "med", "low"))
    return agg.rename(columns={"id.orig_h":"attacker_ip","id.resp_h":"target_ip"})

def detect_icmp_flood(df: pd.DataFrame, icmp_cfg: dict, short: int, long: int) -> pd.DataFrame:
    proto = df["proto"].str.lower()
    svc   = df["service"].str.lower()
    m = (proto=="icmp") | (svc=="icmp")
    icdf = df[m].copy()
    if icdf.empty: return pd.DataFrame()

    ws = int(icmp_cfg.get("short_window_seconds", short))
    wl = int(icmp_cfg.get("long_window_seconds",  long))
    th_src_s = int(icmp_cfg.get("src_total_threshold_short",   150))
    th_src_l = int(icmp_cfg.get("src_total_threshold_long",    800))
    th_pair_s= int(icmp_cfg.get("pair_threshold_short",        100))
    th_pair_l= int(icmp_cfg.get("pair_threshold_long",         400))
    th_vict_s= int(icmp_cfg.get("victim_total_threshold_short",300))
    th_vus_s = int(icmp_cfg.get("victim_unique_src_threshold_short", 25))
    th_vict_l= int(icmp_cfg.get("victim_total_threshold_long", 1200))
    th_vus_l = int(icmp_cfg.get("victim_unique_src_threshold_long", 80))
    th_pps   = float(icmp_cfg.get("pps_threshold_short", 500))
    rr_max   = float(icmp_cfg.get("reply_ratio_max", 0.1))
    enforce_echo = bool(icmp_cfg.get("enforce_echo_like", True))
    src_wh = set(icmp_cfg.get("src_ip_whitelist", []))
    dst_wh = set(icmp_cfg.get("dst_ip_whitelist", []))

    icdf["wS"] = time_bin(icdf["ts"], ws)
    icdf["wL"] = time_bin(icdf["ts"], wl)

    if enforce_echo and "history" in icdf.columns:
        echo_like = icdf["history"].str.contains("D", na=False) & (~icdf["history"].str.contains("d", na=False))
        icdf = icdf[echo_like]

    g_s_src = icdf.groupby(["id.orig_h","wS"], sort=False)
    g_l_src = icdf.groupby(["id.orig_h","wL"], sort=False)
    g_s_pair= icdf.groupby(["id.orig_h","id.resp_h","wS"], sort=False)
    g_l_pair= icdf.groupby(["id.orig_h","id.resp_h","wL"], sort=False)
    g_s_vic = icdf.groupby(["id.resp_h","wS"], sort=False)
    g_l_vic = icdf.groupby(["id.resp_h","wL"], sort=False)

    s_src = g_s_src["ts"].transform("size")
    l_src = g_l_src["ts"].transform("size")
    s_pair= g_s_pair["ts"].transform("size")
    l_pair= g_l_pair["ts"].transform("size")

    v_rows_s = g_s_vic["ts"].transform("size")
    v_rows_l = g_l_vic["ts"].transform("size")
    v_usrc_s = g_s_vic["id.orig_h"].transform("nunique")
    v_usrc_l = g_l_vic["id.orig_h"].transform("nunique")

    sums_s = g_s_src[["orig_pkts","resp_pkts","duration"]].transform("sum")
    pps = (sums_s["orig_pkts"] / sums_s["duration"].clip(lower=1.0)).fillna(0.0)
    rr  = (sums_s["resp_pkts"] / sums_s["orig_pkts"].replace(0,np.nan)).fillna(0.0)

    ok_src = ~icdf["id.orig_h"].isin(src_wh)
    ok_dst = ~icdf["id.resp_h"].isin(dst_wh)

    hit = (
        (s_src >= th_src_s) | (l_src >= th_src_l) |
        (s_pair >= th_pair_s) | (l_pair >= th_pair_l) |
        (v_rows_s >= th_vict_s) | (v_usrc_s >= th_vus_s) |
        (v_rows_l >= th_vict_l) | (v_usrc_l >= th_vus_l) |
        ((pps >= th_pps) & (rr <= rr_max))
    ) & ok_src & ok_dst

    cand = icdf[hit].copy()
    if cand.empty: return pd.DataFrame()

    agg = cand.groupby(["id.resp_h"]).agg(
        total=("ts","size"),
        uniq_src=("id.orig_h","nunique")
    ).reset_index()
    agg["type"]="icmp_flood"
    agg["severity"]=np.where(agg["uniq_src"]>=th_vus_l,"high",
                      np.where(agg["uniq_src"]>=th_vus_s,"med","low"))
    return agg.rename(columns={"id.resp_h":"target_ip"})

def detect_dns_flood(df: pd.DataFrame, dns_cfg: dict, short: int, long: int) -> pd.DataFrame:
    if df.empty: return pd.DataFrame()
    udp = df[df["proto"].str.lower()=="udp"].copy()
    if udp.empty: return pd.DataFrame()

    focus_ports = set(dns_cfg.get("focus_ports", [53]))
    req_focus   = bool(dns_cfg.get("require_focus", True))
    ws = int(dns_cfg.get("short_window_seconds", short))
    wl = int(dns_cfg.get("long_window_seconds",  long))
    th_rows_S = int(dns_cfg.get("victim_rows_threshold_short", 400))
    th_usrc_S = int(dns_cfg.get("victim_unique_src_threshold_short", 35))
    th_rows_L = int(dns_cfg.get("victim_rows_threshold_long",  2000))
    th_usrc_L = int(dns_cfg.get("victim_unique_src_threshold_long", 140))
    en_ratio  = bool(dns_cfg.get("enable_udp_bytes_ratio", True))
    th_ratio  = float(dns_cfg.get("udp_bytes_ratio_threshold", 6.0))
    th_rows_R = int(dns_cfg.get("udp_min_rows_for_ratio", 80))

    if req_focus:
        udp = udp[udp["id.resp_p"].isin(focus_ports)]
    if udp.empty: return pd.DataFrame()

    udp["wS"] = time_bin(udp["ts"], ws)
    udp["wL"] = time_bin(udp["ts"], wl)
    gS = udp.groupby(["id.resp_h","wS"], sort=False)
    gL = udp.groupby(["id.resp_h","wL"], sort=False)

    n_rows_S = gS["ts"].transform("size")
    n_usrc_S = gS["id.orig_h"].transform("nunique")
    n_rows_L = gL["ts"].transform("size")
    n_usrc_L = gL["id.orig_h"].transform("nunique")

    hit = ( (n_rows_S >= th_rows_S) | (n_usrc_S >= th_usrc_S) |
            (n_rows_L >= th_rows_L) | (n_usrc_L >= th_usrc_L) )

    if en_ratio:
        sumsS = gS[["orig_bytes","resp_bytes"]].transform("sum")
        ratio = np.where(sumsS["orig_bytes"]>0, sumsS["resp_bytes"]/np.maximum(sumsS["orig_bytes"],1.0), 0.0)
        hit = hit | ( (n_rows_S >= th_rows_R) & (ratio >= th_ratio) )

    cand = udp[hit].copy()
    if cand.empty: return pd.DataFrame()

    agg = cand.groupby(["id.resp_h"]).agg(
        total=("ts","size"),
        uniq_src=("id.orig_h","nunique")
    ).reset_index()
    agg["type"]="dns_flood"
    agg["severity"]=np.where(agg["uniq_src"]>=th_usrc_L,"high",
                      np.where(agg["uniq_src"]>=th_usrc_S,"med","low"))
    return agg.rename(columns={"id.resp_h":"target_ip"})

def detect_ddos(df: pd.DataFrame, ddos_cfg: dict, short: int, long: int) -> pd.DataFrame:
    if df.empty: return pd.DataFrame()
    # kurban-merkezli
    ws = int(ddos_cfg.get("short_window_seconds", short))
    wl = int(ddos_cfg.get("long_window_seconds",  long))

    proto_scope = set(x.lower() for x in ddos_cfg.get("proto_scope", ["tcp","udp"]))
    ex_ports    = set(ddos_cfg.get("exclude_ports", [22,3389]))

    tcp_focus = set(ddos_cfg.get("tcp_focus_ports", [80,443,8080,8443,8000,8081]))
    udp_focus = set(ddos_cfg.get("udp_focus_ports", [53,123,1900,161,389,11211,111,69,137,5353]))
    req_victim_focus = bool(ddos_cfg.get("require_victim_focus", True))

    th_vsrc_S = int(ddos_cfg.get("victim_unique_src_threshold_short", 120))
    th_vrows_S= int(ddos_cfg.get("victim_rows_threshold_short", 2000))
    th_vpair_S= int(ddos_cfg.get("victim_pairs_threshold_short", 1200))
    th_vsrc_L = int(ddos_cfg.get("victim_unique_src_threshold_long",  600))
    th_vrows_L= int(ddos_cfg.get("victim_rows_threshold_long",  6000))
    th_vpair_L= int(ddos_cfg.get("victim_pairs_threshold_long",  2400))
    th_s0     = float(ddos_cfg.get("s0_ratio_threshold", 0.40))
    th_synm   = float(ddos_cfg.get("syn_noack_mean_threshold", 0.35))

    udp_amp_ports = set(ddos_cfg.get("udp_amplification_ports", [53,123,1900,161,389,11211,111,69,137,5353]))
    amp_mult = float(ddos_cfg.get("udp_amplification_multiplier", 0.6))
    port_mults = {str(k):float(v) for k,v in ddos_cfg.get("udp_amplification_multipliers", {}).items()}

    df2 = df[df["proto"].str.lower().isin(proto_scope)].copy()
    if df2.empty: return pd.DataFrame()
    df2 = df2[~df2["id.resp_p"].isin(ex_ports)]
    if df2.empty: return pd.DataFrame()
    df2["wS"] = time_bin(df2["ts"], ws)
    df2["wL"] = time_bin(df2["ts"], wl)

    # fokus: (kurban portları)
    is_tcp_focus = (df2["proto"].str.lower()=="tcp") & (df2["id.resp_p"].isin(tcp_focus))
    is_udp_focus = (df2["proto"].str.lower()=="udp") & (df2["id.resp_p"].isin(udp_focus))
    victim_focus = is_tcp_focus | is_udp_focus
    if req_victim_focus:
        df2 = df2[victim_focus]
        if df2.empty: return pd.DataFrame()

    gS = df2.groupby(["id.resp_h","wS"], sort=False)
    gL = df2.groupby(["id.resp_h","wL"], sort=False)

    v_rows_S = gS["ts"].transform("size").astype(int)
    v_pairs_S= gS["_pair_orig_hp"].transform("nunique")
    v_usrc_S = gS["id.orig_h"].transform("nunique")

    v_rows_L = gL["ts"].transform("size").astype(int)
    v_pairs_L= gL["_pair_orig_hp"].transform("nunique")
    v_usrc_L = gL["id.orig_h"].transform("nunique")

    # kalite sinyalleri
    v_s0_S = gS["conn_state"].transform(lambda s: s.isin(FAIL_STATES).sum()) / v_rows_S.clip(lower=1)
    v_synm_S = gS["syn_noack"].transform("mean")

    # UDP amplification multiplier (eşikleri düşür)
    is_udp = (df2["proto"].str.lower()=="udp")
    is_amp = is_udp & df2["id.resp_p"].isin(udp_amp_ports)
    port_mult = df2["id.resp_p"].astype(str).map(lambda p: float(port_mults.get(p, amp_mult)))
    eff_vsrc_S  = np.where(is_amp, th_vsrc_S  * port_mult, th_vsrc_S)
    eff_vrows_S = np.where(is_amp, th_vrows_S * port_mult, th_vrows_S)
    eff_vpair_S = np.where(is_amp, th_vpair_S * port_mult, th_vpair_S)
    eff_vsrc_L  = np.where(is_amp, th_vsrc_L  * port_mult, th_vsrc_L)
    eff_vrows_L = np.where(is_amp, th_vrows_L * port_mult, th_vrows_L)
    eff_vpair_L = np.where(is_amp, th_vpair_L * port_mult, th_vpair_L)

    hit = (
        (v_usrc_S >= eff_vsrc_S) | (v_rows_S >= eff_vrows_S) | (v_pairs_S >= eff_vpair_S) |
        (v_usrc_L >= eff_vsrc_L) | (v_rows_L >= eff_vrows_L) | (v_pairs_L >= eff_vpair_L) |
        (v_s0_S >= th_s0) | (v_synm_S >= th_synm)
    )

    cand = df2[hit].copy()
    if cand.empty: return pd.DataFrame()

    agg = cand.groupby("id.resp_h").agg(
        total=("ts","size"),
        uniq_src=("id.orig_h","nunique"),
        uniq_pairs=(" _pair_orig_hp".strip(),"nunique")
    ).reset_index()
    agg["type"]="ddos"
    agg["severity"]=np.where(agg["uniq_src"]>=th_vsrc_L,"high",
                      np.where(agg["uniq_src"]>=th_vsrc_S,"med","low"))
    return agg.rename(columns={"id.resp_h":"target_ip"})

# -------------------------
# Main
# -------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scores", default="reports/scores/scores_stream.csv")
    ap.add_argument("--out",    default="reports/scores/alerts_rule_stream.csv")
    ap.add_argument("--rules-dir", default="conf/rules")
    ap.add_argument("--short", type=int, default=30, help="kısa pencere (s)")
    ap.add_argument("--long",  type=int, default=600, help="uzun pencere (s)")
    ap.add_argument("--window",type=int, default=900, help="okunacak zaman penceresi (s)")
    ap.add_argument("--max-rows", type=int, default=200000)
    args = ap.parse_args()

    rules_dir = Path(args.rules_dir)
    df = read_window(Path(args.scores), max(args.window, args.long), args.max_rows)
    if df.empty:
        print("[rules] window empty")
        return
    df = ensure_cols(df)

    # config’ler (dosya yoksa default ile devam)
    scan_cfg = load_json(rules_dir, "scan", {})
    brute_cfg= load_json(rules_dir, "brute", {})
    icmp_cfg = load_json(rules_dir, "icmp_flood", {})
    dns_cfg  = load_json(rules_dir, "dns", {})
    ddos_cfg = load_json(rules_dir, "ddos", {})

    alerts = []

    ps = detect_portscan(df, scan_cfg, args.short, args.long)
    if not ps.empty: alerts.append(ps)

    bf = detect_bruteforce(df, brute_cfg, args.short, args.long)
    if not bf.empty: alerts.append(bf)

    ic = detect_icmp_flood(df, icmp_cfg, args.short, args.long)
    if not ic.empty: alerts.append(ic)

    dn = detect_dns_flood(df, dns_cfg, args.short, args.long)
    if not dn.empty: alerts.append(dn)

    dd = detect_ddos(df, ddos_cfg, args.short, args.long)
    if not dd.empty: alerts.append(dd)

    if not alerts:
        print("[rules] no alerts")
        return

    out = pd.concat(alerts, ignore_index=True, sort=False)
    out["ts_generated"] = now_ts()
    # kolonları düzelt
    cols = ["ts_generated","type","severity","attacker_ip","target_ip","total","uniq_src","uniq_hosts","uniq_ports","uniq_pairs","fail_ratio","attempts"]
    for c in cols:
        if c not in out.columns: out[c] = np.nan
    out = out[cols]
    append_csv(Path(args.out), out)
    print(f"[rules] wrote {len(out)} alerts")

if __name__ == "__main__":
    main()
