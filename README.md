# Security Pipeline — AI-Powered Network Attack Detector

**[日本語はこちら / Japanese below](#日本語)**

![Attack Detection](https://img.shields.io/badge/Attack%20Detection-100%25-brightgreen)
![False Positive](https://img.shields.io/badge/False%20Positive-0%25-brightgreen)
![Language](https://img.shields.io/badge/language-Python-blue)

---

## What it does

Detects attackers who **look like legitimate users** by analyzing the context of network sessions — not just individual packets.

A two-stage pipeline (rule-based filter + AI judgment) automatically extracts attack sessions from massive logs and generates detailed reports.

---

## Proven Performance

| Metric | Result |
|--------|--------|
| Rows scanned | **445,909** |
| Processing time | **96 minutes** |
| Attack detection rate | **100%** |
| False positive rate | **0%** |
| Miss rate | **0%** |

> Dataset: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — University of New Brunswick, Canada

---

## How it works

```
Raw logs (hundreds of thousands of rows)
        ↓
[Step 1] Rule-based filter   ← Removes 99% of noise in 14 seconds
        ↓
[Step 2] AI judgment layer   ← Detects attacks disguised as normal traffic
        ↓
[Step 3] Report generation   ← Outputs with SIEM/IDS signatures
```

### Why it can detect hackers who look like legitimate users

Attack tools leave **tool-specific fingerprints**:

- Fixed TCP window size (e.g. `Init_Win=259`)
- Identical byte counts across sessions (e.g. `Bwd=188 bytes` in every session)
- Zero payload + URG flag combination (reconnaissance signature)
- Missing FIN flag on disconnect (forced termination after auth failure)

Human-operated sessions never show this level of statistical uniformity.

---

## Detected Attack Types

| Attack | Description |
|--------|-------------|
| SSH-Patator TypeA | Port probing / reconnaissance |
| SSH-Patator TypeB | SSH brute-force authentication |
| FTP-Patator TypeA | FTP immediate-reject brute-force |
| FTP-Patator TypeB | FTP multi-packet brute-force |
| FTP-Patator TypeC | FTP partial-connection brute-force |

---

## Sample Reports

- [Attack Pattern Analysis](attack_analysis_report.md) — Detailed reasoning for each attack judgment
- [Mixed Dataset Detection Test](mixed_classification_report.md) — Accuracy verification with normal traffic mixed in
- [Full Scan Report](pipeline_report.md) — Results of 445,909-row scan

---

## Setup

```bash
git clone https://github.com/YoshiOnGithub/security-pipeline.git
cd security-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with your API key:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

---

## Usage

```bash
# Test run (first batch only)
python security_pipeline.py --max-batches 1

# Full scan
python security_pipeline.py

# Resume from checkpoint
python security_pipeline.py --start-batch 100
```

---

## Supported Log Formats

Currently: CICFlowMeter CSV (network flow logs)

Planned:
- Linux server logs
- Windows Event Logs
- AWS CloudTrail
- Network device logs

---

## Background

Built after successfully creating an AI hacker that intrudes via legitimate login methods — and then detecting it. Validated against real incident data, achieving detection accuracy comparable to commercial SIEM tools as a solo developer project.

---

## License

MIT License

---

## Demo / Contact

Live demos using real log data are available. Feel free to open an Issue or Discussion.

---
---

<a name="日本語"></a>

# Security Pipeline — AI駆動ネットワーク攻撃検知システム

**[English above](#security-pipeline--ai-powered-network-attack-detector)**

---

## 何ができるか

正規のログイン手順を踏んでいるにもかかわらず、**文脈から攻撃者と判断する**ことができます。

ルールベースとAIの2段階処理により、大量のログから攻撃セッションだけを自動抽出してレポートを生成します。

---

## 実証済みの性能

| 指標 | 結果 |
|------|------|
| スキャン対象 | **445,909行** |
| 処理時間 | **96分** |
| 攻撃検知率 | **100%** |
| 誤検知率 | **0%** |
| 見逃し率 | **0%** |

> 使用データセット: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)（カナダ・ニューブランズウィック大学）

---

## 仕組み

```
生ログ（数十万行）
        ↓
【Step 1】ルールベースフィルタ  ← 14秒で99%のノイズを除去
        ↓
【Step 2】AI判断レイヤー       ← 文脈を見て攻撃か正常かを判定
        ↓
【Step 3】レポート自動生成     ← SIEM/IDSシグネチャ付きで出力
```

### なぜ「正規ログインに見えるハッカー」を検知できるか

攻撃ツールは以下のような**ツール固有の痕跡**を残します。

- TCPウィンドウサイズの固定値（例：`Init_Win=259`）
- 送受信バイト数の完全一致（例：全セッションで`Bwd=188bytes`）
- ゼロペイロード＋URGフラグの組み合わせ（偵察の証拠）
- FINフラグなしの切断（認証失敗後の強制切断）

人間が操作するセッションではこのような均一性は統計的に発生しません。

---

## 検知できる攻撃

| 攻撃種別 | 説明 |
|---------|------|
| SSH-Patator TypeA | ポートプローブ・偵察 |
| SSH-Patator TypeB | SSH認証総当たり |
| FTP-Patator TypeA | FTP即時拒否型総当たり |
| FTP-Patator TypeB | FTP多パケット認証総当たり |
| FTP-Patator TypeC | FTP部分接続型総当たり |

---

## 出力されるレポートのサンプル

- [攻撃パターン詳細分析](attack_analysis_report.md) — 攻撃と判断した根拠を詳述
- [混在データ検知テスト](mixed_classification_report.md) — 正常トラフィックと混在した状態での精度検証
- [フルスキャンレポート](pipeline_report.md) — 44万行スキャンの実行結果

---

## セットアップ

```bash
git clone https://github.com/YoshiOnGithub/security-pipeline.git
cd security-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`.env`ファイルを作成してAPIキーを設定：

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

---

## 実行方法

```bash
# テスト実行（最初の1バッチ）
python security_pipeline.py --max-batches 1

# フルスキャン
python security_pipeline.py

# 途中から再開
python security_pipeline.py --start-batch 100
```

---

## 対応ログ形式

現在：CICFlowMeter形式のCSV（ネットワークフローログ）

今後対応予定：
- Linuxサーバーログ
- Windowsイベントログ
- AWS CloudTrail
- ネットワーク機器ログ

---

## 開発背景

AIハッカーを自作して攻撃させ、正規のログイン方法で侵入したハッカーの検知に成功したことをきっかけに開発。実際のインシデントデータを使って検証を重ねた結果、商用SIEMツールに匹敵する検知精度を個人開発で実現しました。

---

## ライセンス

MIT License

---

## 連絡先・デモのご依頼

実際のログデータを使ったデモが可能です。お気軽にIssueまたはDiscussionからご連絡ください。
