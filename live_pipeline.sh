#!/usr/bin/env bash
# live_pipeline.sh — tcpdump → Zeek → features → ML → (ML pos/neg ayrımı) → Rules → Merge → Actions
set -euo pipefail

# === AYARLAR ===
REPO="/home/huseyin/ida-netids"
IFACE="enp44s0"                               # ip link ile doğrula
PCAP_DIR="$REPO/data/live/pcaps"
PROC_DIR="$REPO/data/live/processed"
LIVE_DIR="$REPO/data/live"
SCORES_DIR="$REPO/reports/scores"
MODEL_DIR="$REPO/models"
SCHEMA="$REPO/data/features/X.columns.txt"
THR_YML="$REPO/conf/thresholds.yml"

# Rules profili: lab (agresif) / prod (konservatif)
RULES_PROFILE="${RULES_PROFILE:-lab}"
RULES_DIR="$REPO/conf/rules-${RULES_PROFILE}"

# ML/Rules/merge pencereleri
SHORT=5
LONG=60
WINDOW=120
MAXROWS=200000
MERGE_WINDOW_SEC=3600
MERGE_MAXROWS=200000
COOLDOWN_SEC=300

# === DİZİNLER/İZİNLER ===
mkdir -p "$PCAP_DIR" "$PROC_DIR" "$LIVE_DIR" "$SCORES_DIR" "$REPO/reports/logs"
sudo chown root:root -R "$REPO/data/live" || true
sudo chmod 755 "$REPO/data" "$LIVE_DIR" "$PCAP_DIR" "$PROC_DIR" || true

# === 30 sn PCAP ROTASYONU (flush için -U) ===
sudo tcpdump -i "$IFACE" -G 30 -w "$PCAP_DIR/cap_%s.pcap" -U -Z root >/dev/null 2>&1 &
TCPDUMP_PID=$!
echo "[tcpdump] pid=$TCPDUMP_PID (iface=$IFACE, rotate=30s)"

cleanup() {
  echo "[trap] stopping…"
  kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

RECENT_SKIP_SEC=3  # çok yeni dosyayı 2–3 sn beklet

# === DÖNGÜ ===
while true; do
  for p in "$PCAP_DIR"/cap_*.pcap; do
    [ -e "$p" ] || { sleep 2; continue; }
    base=$(basename "$p")
    done_flag="$PROC_DIR/${base}.done"
    [ -f "$done_flag" ] && continue

    now=$(date +%s)
    ts=${base#cap_}; ts=${ts%.pcap}
    [[ "$ts" =~ ^[0-9]+$ ]] || { echo "[warn] bad ts in $base"; touch "$done_flag"; continue; }
    (( now - ts < RECENT_SKIP_SEC )) && continue

    echo "[*] processing $base"

    # --- Zeek → conn.log(.json) (çıktı LIVE_DIR'e) ---
    pushd "$LIVE_DIR" >/dev/null

    # 1) Standart çalışma — Zeek tüm default script ağacı ile
    zeek -C -r "$p" LogAscii::use_json=T >/dev/null 2>&1 || true

    # 2) Fallback: conn.log(.json) yoksa SADECE "conn" paketini yükleyerek dene
    if [ ! -s "conn.log" ] && [ ! -s "conn.log.json" ]; then
      if zeek -C -r "$p" base/protocols/conn LogAscii::use_json=T >/dev/null 2>&1; then
        :
      elif zeek -C -r "$p" protocols/conn LogAscii::use_json=T >/dev/null 2>&1; then
        :
      elif zeek -C -r "$p" policy/protocols/conn LogAscii::use_json=T >/dev/null 2>&1; then
        :
      else
        zeek -C -r "$p" conn LogAscii::use_json=T >/dev/null 2>&1 || true
      fi
    fi

    # 3) Kaynak dosyayı seç (var ve boş değilse)
    SRC=""
    if   [ -f "conn.log.json" ] && [ -s "conn.log.json" ]; then SRC="conn.log.json"
    elif [ -f "conn.log"      ] && [ -s "conn.log"      ]; then SRC="conn.log"
    fi

    # 4) Hâlâ yoksa bu pcap'i atla
    if [ -z "$SRC" ]; then
      echo "[warn] no conn.log for $base (maybe no connections?)"
      popd >/dev/null
      touch "$done_flag"
      continue
    fi

    # 5) JSON mu TSV mi? Güvenli dönüştür
    if head -n1 "$SRC" | grep -q '^{'; then
      # JSON satırları → CSV (15 kolon)
      jq -r '["ts","uid","orig_h","orig_p","resp_h","resp_p","proto","service","conn_state",
               "duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","missed_bytes"],
             (. as $x | [ (.ts//null), (.uid//null),
                          ($x["id.orig_h"]//null), ($x["id.orig_p"]//null),
                          ($x["id.resp_h"]//null), ($x["id.resp_p"]//null),
                          (.proto//null), (.service//null), (.conn_state//null),
                          (.duration//null), (.orig_bytes//null), (.resp_bytes//null),
                          (.orig_pkts//null), (.resp_pkts//null), (.missed_bytes//null) ] )
             | @csv' "$SRC" > conn_raw.csv
    else
      # TSV → CSV (aynı 15 kolon)
      zeek-cut -d ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state \
                   duration orig_bytes resp_bytes orig_pkts resp_pkts missed_bytes < "$SRC" \
      | awk -F'\t' 'BEGIN{
          print "ts,uid,orig_h,orig_p,resp_h,resp_p,proto,service,conn_state,duration,orig_bytes,resp_bytes,orig_pkts,resp_pkts,missed_bytes"
        }{
          gsub(/\t/,","); print
        }' > conn_raw.csv
    fi

    # temizlik
    rm -f conn.log conn.log.json
    popd >/dev/null

    # --- Özellik → Skor ---
    python3 "$REPO/src/features/02_build_features.py" \
      --in "$LIVE_DIR/conn_raw.csv" \
      --X "$LIVE_DIR/X.parquet" \
      --ybin "$LIVE_DIR/y_bin.csv" \
      --ymulti "$LIVE_DIR/y_multi.csv" >/dev/null

    python3 "$REPO/src/serve/score_batch.py" \
      --X "$LIVE_DIR/X.parquet" \
      --out "$SCORES_DIR/live_scores.csv" \
      --models-dir "$MODEL_DIR" \
      --calibrator "$MODEL_DIR/bin_isotonic.pkl" \
      --thresholds "$THR_YML" \
      --schema "$SCHEMA" >/dev/null

    # === ML pozitif/negatif ayrımı + stream dosyalarına append ===
    python3 - <<'PY'
import os, yaml, pandas as pd
thr = float(yaml.safe_load(open("conf/thresholds.yml"))["binary"]["threshold"])
raw = pd.read_csv("data/live/conn_raw.csv")
sc  = pd.read_csv("reports/scores/live_scores.csv")
df = raw.join(sc)
df["margin"] = df["p_cal"] - thr

# Tüm skorlar → append
out_all = "reports/scores/scores_stream.csv"
df.to_csv(out_all, mode="a", index=False, header=not os.path.exists(out_all))

# ML pozitif/negatif akışları
ml_pos = df[df["pred"] == 1].copy()
ml_neg = df[df["pred"] == 0].copy()

out_ml_alerts = "reports/scores/alerts_stream.csv"
if not ml_pos.empty:
    ml_pos.to_csv(out_ml_alerts, mode="a", index=False, header=not os.path.exists(out_ml_alerts))

out_ml_neg = "reports/scores/scores_stream_mlneg.csv"
if not ml_neg.empty:
    ml_neg.to_csv(out_ml_neg, mode="a", index=False, header=not os.path.exists(out_ml_neg))

print(f"[ALERTS] ml_pos={len(ml_pos)} ml_neg={len(ml_neg)} thr={thr:.3f}")
PY

    # --- RULES: ML-neg akıştan kural motorunu koştur ---
    python3 "$REPO/src/serve/rules_engine_v2.py" \
      --scores "$SCORES_DIR/scores_stream_mlneg.csv" \
      --out    "$SCORES_DIR/alerts_rule_stream.csv" \
      --rules-dir "$RULES_DIR" \
      --short "$SHORT" --long "$LONG" --window "$WINDOW" --max-rows "$MAXROWS" \
      >/dev/null 2>&1 || true

    # --- EXTRA RULE: REJ/S0 port-scan hızlı tespit ---
    python3 "$REPO/src/serve/rules_rejscan_fast.py" >/dev/null 2>&1 || true

    # --- MERGE: ML + Rules tek birleşik akış ---
    python3 "$REPO/src/serve/merge_alerts.py" \
      --ml "$SCORES_DIR/alerts_stream.csv" \
      --rules "$SCORES_DIR/alerts_rule_stream.csv" \
      --out "$SCORES_DIR/alerts_merged_stream.csv" \
      --window-sec "$MERGE_WINDOW_SEC" --max-rows "$MERGE_MAXROWS" --cooldown-sec "$COOLDOWN_SEC" \
      >/dev/null 2>&1 || true

    # --- ACTIONS: son merge turuna göre ANINDA ban ---
    sudo -n python3 "$REPO/src/serve/actions.py" \
      --in "$SCORES_DIR/alerts_merged_stream.csv" \
      --only-latest \
      --min-severity med \
      --sources rules,ml \
      --ipset ml_blacklist \
      --block-sec 600 \
      --cooldown-sec 60 \
      --proof-min 1 \
      --ban-limit 100 \
      --whitelist 192.168.1.36 \
      --ensure-fw \
      --quiet \
      >/dev/null 2>&1 || true

    touch "$done_flag"
  done
  sleep 2
done
