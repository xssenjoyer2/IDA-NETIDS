# IDA-NETIDS

## Genel Bakış

Bu uygulama Zeek aracılığı ile ağ trafiğini gerçek zamanlı olarak izleyerek olası ağ içi saldırıları tespit edip otomatik olarak engelleyen bir IDS/IPS sistemidir. Mimarimiz LightGBM ile eğitilen yapay zeka ve kural tabanlı yapıdan oluşmaktadır. Ağ trafiği üzerindeki paketler öncelikle ML yapısı tarafından analiz edilmekte ve saldırı vektörleri içerip içermediği analiz edilmektedir. ML tarafından herhangi bir saldırı vektörü içermediği tespit edilip "normal" kabul edilen akışlar ayrıca kural tabanlı sistem tarafından ikinci bir analiz aşamasına tabii tutulup buradaki eşik değerleri ile ilgili paketin tekrardan bir atak vektörü içerip içermediği sorgulanmaktadır. Böylece ağ içi saldırıların daha kapsamlı bir analizle engellenmesi hedeflenmektedir.

Süreç ağ paketlerinin tcpdump ile yakalanıp Zeek tarafından akış kayıtlarına dönüştürülmesi ile başlar. Bu kayıtlar özellik çıkarımından geçip LightGBM tabanlı ML modeli ile column bilgileri , ML skorlaması ile kapsamlı bir biçimde analiz edilerek "normal/attack" olarak adlandırılır. ML kısmının yetersiz kalabilme dolayısıyla atak vekörlerinin aradan kaçabilme ihtimaline karşı kural tabanlı motor "normal" etiketli veriler üzerinde ikinci bir analiz gerçekleştirir.Bu analiz kısa ve uzun zaman pencerelerinde gerçekleşebilen saldırılara yönelik eşik değerleri baz alınarak "alarm" üretibilecek şekilde tasarlanmıştır. ML veya ML+kural tabanı yapısından geçen paketler tek bir akış halinde raporlanır ve "actions.py" adında aksiyon alacağımız kısıma aktarılır.Burada ML veya kural tabanı kısmında "alarm" üretilmişse ilgili saldırgan IP'leri otomatik olarak ipset/iptables üzerinden geçici olarak engellenir.

Ek olarak kural tabanlı sistemde her bir saldırı için ( DDoS , icmp_flood , bruteForce , port scan , dns flooding vb.) için ayrı ayrı .json dosyaları bulunmakta bunlardaki eşik değerleri değiştirilerek farklı saldırı yöntemlerine karşı önlem alınabilmektedir.

Streamlit paneli ile ML ve kural tabanından gelen birleşik "alarm" yapılarını canlı olarak web arayüzünde görüntülenebilmektedir. Kullanıcı bu web arayüzünde alarmın şiddeti , kaynağı , ne tarafından tespit edildiği , hangi atak vektörünü içerdiği gibi bilgileri görebilmektedir. Bu web arayüzünde normal ağ trafiği listelenmez yalnızca "alarm" üreten ve banlanan paket içerikleri kapsamlı bir biçimde kayıt altına alınır.

## live_pipeline.sh

`live_pipeline.sh`, bütün mimariyi uçtan uca canlı çalıştıran ana orkestrasyon betiğidir. Aşağıdaki zinciri otomatik ve sürekli döngüde işletir:

- **Paket yakalama:** tcpdump 30 saniyede bir dönen PCAP dosyaları üretir (varsayılan ağ arayüzü **enp44s0**).
- **Zeek ayrıştırma:** PCAP → conn.log(.json) → güvenli CSV (conn_raw.csv).
- **Özellik çıkarımı:** 02_build_features.py ile modelin beklediği X matrisi (parquet) üretilir.
- **ML skorlaması:** score_batch.py ile LGBM tahmini + izotonik kalibrasyon + threshold → live_scores.csv ve ML pozitif (alerts) / negatif (mlneg) akışları.
- **Kural motoru:** rules_engine_v2.py ML-neg akışını kısa/uzun pencerelerde analiz eder; portscan/bruteforce/ICMP-DNS flood/DDoS alarmları üretir.
- **Hızlı REJ/S0 tarama kuralı:** rules_rejscan_fast.py 3 dakikalık pencerede hızlı port-taramalarını yakalar.
- **Birleştirme:** merge_alerts.py ML + Rules alarmlarını tek akışta toplar → alerts_merged_stream.csv.
- **Otomatik aksiyon:** actions.py filtrelere uyan saldırgan IP’leri ipset içine ekleyip (geçici ban) iptables üzerinde DROP uygulatır.
- **Gözlem:** (opsiyonel) dash_alerts.py Streamlit paneli birleşik alarmları ve son banları gösterir.

Bu akışta dosya kilitleri, boş/bozuk dosya toleransı ve fallback Zeek çağrıları gibi pratik sağlamlık önlemleri bulunur.

Çalıştırmak için:
```bash
./live_pipeline.sh
streamlit run dash_alerts.py
```

Bu komutlarla canlı pipeline başlar ve web arayüzü üzerinden yakalanan paketler incelenebilir.

## conf/

- **service_map.yml:** Zeek’in ham service alanlarını normalize etmek için kullanılır. Farklı yazılış varyasyonları (örn. "quic, ssl") veya keşif servisleri (ssdp, mdns, llmnr) tek bir kategori altında birleştirilir. Bu sayede model ve kural motoru daha tutarlı girdilerle çalışır. Tanımsız değerler "other" etiketiyle işaretlenir.
- **thresholds.yml / thresholds_test.yml:** ML tarafında kullanılan karar eşiğini (0–1 arası) ve hedeflenen precision / FPR oranlarını tanımlar.
- **rules-lab/** ve **rules-prod/**: Her saldırı tipine özel JSON kurallarını içerir (örn. DDoS, brute force, scan). Bu kurallar kısa/uzun zaman pencerelerinde eşik değerlerini ayarlayarak farklı ağlara kolay uyarlanabilir.

## src/

- **prep/**: Eğitim öncesi veriyi normalize eden scriptler (ör. 01_load_and_normalize.py).
- **features/**: Özellik çıkarımı (02_build_features.py).
- **train/**: Model eğitim ve eşik kalibrasyonu (03_train_binary.py, 04_calibrate_threshold.py). Eğitim çıktıları repoya dahil edilmemiştir.
- **serve/**: Canlı ortamda çalışan bileşenler:
  - **score_batch.py**: ML modelleriyle skor üretimi.
  - **rules_engine_v2.py**: JSON configlere göre kural tabanlı analiz.
  - **rules_rejscan_fast.py**: Hızlı port tarama tespiti.
  - **merge_alerts.py**: ML + Rules alarmlarını tek akışta birleştirir.
  - **actions.py**: Tespit edilen saldırgan IP’leri ipset/iptables üzerinden banlar.

## data/

- **raw/**: Ham veri (ör. conn_from_zeek_clean.csv).
- **interim/**: Normalize edilmiş birleşik veri (combined_raw.csv).
- **features/**: Özellik matrisleri (X.parquet, y_bin.csv, y_multi.csv).
- **live/**: Canlı pipeline sırasında üretilen akış dosyaları (conn_raw.csv, live_scores.csv).

## models/

- Eğitim sonrası üretilen LightGBM modelleri (bin_lgbm_f*.pkl) ve kalibrasyon dosyası (bin_isotonic.pkl).
- **manifest.json**: Hangi şema ve hangi modellerle eğitim yapıldığını özetler.
- Dosyalar boyut nedeniyle repoya dahil edilmemiştir.

## reports/

- Eğitim ve test çıktılarının tutulduğu çalışma alanı.
- **scores/**: Canlı akış alarmları ve birleşik skorlar (alerts_merged_stream.csv).
- **metrics/**: Model doğrulama metrikleri.
- Eğitim çıktı dosyaları repoya dahil edilmemiş, yalnızca örnek raporlar bırakılmıştır.

## Eğitim Verisi

Model, ortalama **230.000 "normal"** ve **430.000 "attack"** etiketli veri ile eğitilmiştir. Attack verilerinin dağılımı yaklaşık olarak:
- 230.000 DDoS
- 81.000 Port scan
- 11.500 Brute force
- kalan kısmı DNS flooding

Bu dağılım LightGBM modellerinin dengeli ve farklı saldırı tiplerini kapsayacak şekilde öğrenmesini sağlamıştır.

## Proje Durumu

## Proje Durumu
Bu proje şu anda **localhost ortamında geliştirme ve test aşamasındadır**.  
DDoS ve DNS flood tespitleri kararlı şekilde çalışmaktadır; port-scan için kısa/uzun süreli bazı durumlarda iyileştirme gerekmektedir.  
Henüz production ortamında uygulanmamış olup, kurulum ve testler Ubuntu + Zeek + tcpdump üzerinde yapılmıştır.



