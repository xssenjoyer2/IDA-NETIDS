#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REJ/S0 port-scan hızlı tespit kuralı.
Kaynak: reports/scores/scores_stream_mlneg.csv (ML-neg akışı)
Çıkış:  reports/scores/alerts_rule_stream.csv
Kural: Son WINDOW_SEC içinde (attacker,target) için farklı DEST port sayısı >= MIN_PORTS → port_scan (med)
"""

import os
import pandas as pd

MLNEG = "reports/scores/scores_stream_mlneg.csv"
OUT   = "reports/scores/alerts_rule_stream.csv"

# ML-neg akışındaki beklenen kolonlar; başlık bozuksa bile güvenle okumak için names veriyoruz:
NAMES = [
    "ts","uid","orig_h","orig_p","resp_h","resp_p","proto","service","conn_state",
    "duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","missed_bytes",
    "p_raw","p_cal","pred","margin"
]

WINDOW_SEC = 180   # son 3 dakika
MIN_PORTS  = 20    # en az 20 farklı hedef port

def main():
    if not os.path.exists(MLNEG) or os.path.getsize(MLNEG) == 0:
        return 0

    # Başlık/bozuk satır toleranslı okuma
    df = pd.read_csv(MLNEG, header=None, names=NAMES, low_memory=False, on_bad_lines="skip")

    # Tip dönüşümleri ve gerekli kolonların temizliği
    df["ts"]     = pd.to_numeric(df["ts"], errors="coerce")
    df["resp_p"] = pd.to_numeric(df["resp_p"], errors="coerce")

    need = ["ts","orig_h","resp_h","resp_p","proto","conn_state"]
    df = df.dropna(subset=need)
    df["resp_p"] = df["resp_p"].astype(int)

    # Sadece TCP ve REJ/S0 durumları (tarama iması)
    df = df[(df["proto"].str.lower() == "tcp") & (df["conn_state"].isin(["REJ","S0"]))].copy()
    if df.empty:
        return 0

    # Zaman penceresi
    cut = df["ts"].max() - WINDOW_SEC
    df = df[df["ts"] >= cut]
    if df.empty:
        return 0

    # (attacker,target) bazında farklı hedef port sayısı
    alerts = []
    for (att, tgt), grp in df.groupby(["orig_h","resp_h"]):
        if grp["resp_p"].nunique() >= MIN_PORTS:
            alerts.append({
                "ts_generated": df["ts"].max(),
                "source": "rules",
                "type": "port_scan",
                "severity": "med",
                "attacker_ip": att,
                "target_ip": tgt,
                "proto": "tcp",
                "service": "",
                "resp_p": "",
                "margin": 0.0,
                "p_cal": ""
            })

    if alerts:
        out_exists = os.path.exists(OUT)
        pd.DataFrame(alerts).to_csv(OUT, mode="a", index=False, header=not out_exists)
        print(f"[FAST-RULE] wrote {len(alerts)} alerts → {OUT}")
        return len(alerts)
    else:
        print("[FAST-RULE] no alert in window")
        return 0

if __name__ == "__main__":
    main()
