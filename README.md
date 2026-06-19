# Secure Sensor Logging berbasis Ascon-AEAD128 dan Ascon-Hash256

Proyek ini mengimplementasikan mekanisme pencatatan data sensor aman untuk kebutuhan makalah kriptografi.

## Inti mekanisme

- **Ascon-AEAD128** dipakai untuk mengenkripsi nilai sensor dan menghasilkan authentication tag.
- **Associated Data (AD)** berisi `sequence_number`, `timestamp`, `device_id`, dan `previous_hash`. AD tidak dienkripsi, tetapi tetap diautentikasi.
- **Ascon-Hash256** dipakai untuk membentuk `record_hash` dan hash chain antar-record.
- **Anchor tepercaya** disimpan pada file `output/anchor_*.json` untuk mendeteksi penghapusan record di bagian akhir log.

## Struktur folder

```text
ascon_sensor_secure_logging/
|-- data/                         # dataset sensor asli hasil generate
|-- docs/                         # dokumen paper final
|-- output/                       # hasil secure log, tabel, dan grafik
|-- src/
|   |-- ascon.py                  # implementasi pure Python Ascon-AEAD128 dan Ascon-Hash256
|   |-- dataset.py                # generator dataset sensor simulasi
|   |-- secure_logger.py          # log aman, hash chain, verifikasi, manipulasi
|   `-- experiments.py            # eksperimen performa dan manipulasi
|-- tests/
|   `-- test_secure_logger.py
|-- run_all.py
`-- requirements.txt
```

## Cara menjalankan

```bash
pip install -r requirements.txt
python run_all.py
```

Default menjalankan eksperimen performa untuk 100, 500, dan 1.000 record agar tidak terlalu lama pada pure Python. Jika ingin mengikuti variasi besar 10.000 record, jalankan:

```bash
python run_all.py --counts 100 1000 10000 --tamper-count 100
```

Output utama:

- `output/summary_performance.csv`
- `output/tamper_results.csv`
- `output/plots/grafik_waktu_proses.png`
- `output/plots/grafik_overhead_ukuran.png`
- `output/plots/grafik_deteksi_manipulasi.png`

## Cara testing singkat

```bash
python -m pytest -p no:cacheprovider tests
```

Opsi `-p no:cacheprovider` dipakai supaya pytest tidak membuat folder cache sementara.

Jika `pytest` belum ada:

```bash
pip install pytest
```

## Catatan keamanan

Kode ini dibuat untuk eksperimen makalah. Python tidak menjamin operasi constant-time penuh, sehingga jangan dipakai sebagai library produksi. Untuk implementasi produksi, gunakan library Ascon yang sudah diaudit atau reference implementation resmi yang sesuai standar.
