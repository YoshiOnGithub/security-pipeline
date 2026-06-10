# Security Pipeline — Context-Aware Network Attack Detector

**[日本語はこちら / Japanese below](#日本語)**

A solo-built, two-stage pipeline that flags attackers who **look like legitimate traffic** by reading the *context* of network sessions — not individual packets.

> **Status:** Working prototype, validated on a public benchmark (CICIDS2017). Not yet tested against live production traffic — see [Honest Limitations](#honest-limitations) before relying on it.

---

## The idea

Modern attackers don't kick the door in. They connect using valid-looking protocols and flows. Packet by packet, everything can look normal. The signal often isn't in any single packet — it's in the **statistical shape of the whole session**.

This pipeline looks for that shape in network flow logs.

```
Raw flow logs (hundreds of thousands of rows)
        v
[Step 1] Rule-based filter   -> strips ~99% of obvious-normal traffic fast
        v
[Step 2] AI judgment layer   -> reads session context, flags the disguised ones
        v
[Step 3] Report generation   -> human-readable reasoning + signatures
```

---

## Why session context beats packet inspection

Automated attack tools leave **statistical fingerprints** that human-driven sessions rarely produce:

* **Fixed TCP window size** across every session (e.g. `Init_Win=259`)
* **Identical byte counts** session after session (e.g. `Bwd=188 bytes` every time)
* **Zero payload + URG flag** together (a reconnaissance tell)
* **Missing FIN on disconnect** (forced cutoff after a failed auth)

No single one of these is proof. The judgment comes from how they cluster — the kind of uniformity a script produces and a person doesn't.

---

## What's actually been tested

This is the part I want to be precise about, because it determines what these results do and don't mean.

| | |
| --- | --- |
| Dataset | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) - a public, **labeled** research benchmark from the University of New Brunswick |
| Rows processed | 445,909 |
| Full-scan runtime | ~96 minutes (rule filter: ~14 seconds) |
| Result on this dataset | Every labeled attack session in the scanned set was correctly classified, with no false positives in the sample |

**Read that result carefully.** CICIDS2017 is a teaching/benchmark dataset where the labels are already known and the attack patterns are well-documented. A strong result here means the pipeline's logic is sound and implemented correctly. It does **not** mean "100% detection in the real world" - that's a different and much harder claim this project has not yet earned. See below.

### Attack types correctly classified on CICIDS2017

| Attack | Description |
| --- | --- |
| SSH-Patator (probe) | Port probing / reconnaissance |
| SSH-Patator (brute) | SSH brute-force authentication |
| FTP-Patator (reject) | FTP immediate-reject brute-force |
| FTP-Patator (multi-packet) | FTP multi-packet brute-force |
| FTP-Patator (partial) | FTP partial-connection brute-force |

---

## Honest Limitations

I'd rather you know these up front than discover them later.

* **Benchmark != production.** Results so far are on a known, labeled dataset. Real network traffic is messier, noisier, and contains attack variants this pipeline has never seen. Performance on live data is **untested** and will be lower than on the benchmark.
* **100% / 0% is a benchmark artifact, not a promise.** Perfect scores on a clean labeled set are common and not, by themselves, evidence of real-world reliability. Treat them as "the logic works on this data," nothing more.
* **Narrow input format.** Currently consumes CICFlowMeter-style CSV only.
* **Detects known *kinds* of tool behavior.** It reasons about statistical uniformity, so a sufficiently slow, randomized, human-paced attack could evade it.
* **Solo project, not an audited product.** No third-party security review.

If you have a use case where these tradeoffs are acceptable - or, better, if you can help test it against messier data - I'd like to hear from you.

---

## Sample reports

* [Attack pattern analysis](attack_analysis_report.md) - the reasoning behind each judgment
* [Mixed-dataset test](mixed_classification_report.md) - accuracy with normal traffic mixed in
* [Full-scan report](pipeline_report.md) - the 445,909-row run

---

## Setup

```bash
git clone https://github.com/YoshiOnGithub/security-pipeline.git
cd security-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

## Usage

```bash
python security_pipeline.py --max-batches 1   # quick test (first batch)
python security_pipeline.py                    # full scan
python security_pipeline.py --start-batch 100  # resume from checkpoint
```

## Supported log formats

Currently: CICFlowMeter CSV (network flow logs).
On the roadmap: Linux server logs, Windows Event Logs, AWS CloudTrail, network-device logs.

---

## Background

I built this to test one idea: that an attacker disguised as legitimate traffic can be caught by reasoning about the *context* of a session rather than matching signatures packet by packet. The benchmark results above are the outcome of that test on labeled data. The honest next step is testing it against data that isn't pre-labeled - that's where the real questions are.

## License

MIT

## Contact

Issues and Discussions are open. If you work with network logs and want to poke holes in this, that's exactly the feedback I'm after.

---
<a name="日本語"></a>
# Security Pipeline - 文脈で見抜くネットワーク攻撃検知器

**[English above](#security-pipeline--context-aware-network-attack-detector)**

正規トラフィックに**見える**攻撃者を、個別パケットではなくセッションの*文脈*から検知する、個人開発の2段パイプラインです。

> **ステータス:** 動作するプロトタイプ。公開ベンチマーク（CICIDS2017）で検証済み。実運用トラフィックでは未検証 - 利用前に[正直な限界](#正直な限界)を必ずお読みください。

---

## 考え方

現代の攻撃者はドアを蹴破りません。正規に見えるプロトコルとフローで接続してきます。パケット単位で見れば、すべて正常に見えることがある。シグナルは単一パケットにはなく、しばしば**セッション全体の統計的な形**に現れます。

このパイプラインは、ネットワークフローログの中からその「形」を探します。

```
生のフローログ（数十万行）
        v
【Step 1】ルールベースフィルタ -> 明らかに正常なトラフィック約99%を高速に除去
        v
【Step 2】AI判断レイヤー       -> セッションの文脈を読み、偽装を炙り出す
        v
【Step 3】レポート生成         -> 判断根拠＋シグネチャを人間可読で出力
```

---

## なぜ文脈がパケット検査に勝るのか

自動化された攻撃ツールは、人間の操作するセッションではまず生じない**統計的な指紋**を残します。

* 全セッションで**固定されたTCPウィンドウサイズ**（例：`Init_Win=259`）
* セッションをまたいで**完全一致するバイト数**（例：毎回`Bwd=188bytes`）
* **ゼロペイロード＋URGフラグ**の同時出現（偵察の兆候）
* **FINなしの切断**（認証失敗後の強制切断）

どれ一つも単独では証拠になりません。判断は、これらがどう束になるか - スクリプトは生むが人間は生まない均一性 - から導かれます。

---

## 実際に検証したこと

ここは正確に書きます。この結果が何を意味し、何を意味しないかを左右するからです。

| | |
| --- | --- |
| データセット | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) - カナダ・ニューブランズウィック大学の公開**ラベル付き**研究用ベンチマーク |
| 処理行数 | 445,909行 |
| フルスキャン時間 | 約96分（ルールフィルタは約14秒） |
| このデータセットでの結果 | スキャン範囲内のラベル付き攻撃セッションをすべて正しく分類。サンプル内で誤検知なし |

**この結果は慎重に読んでください。** CICIDS2017は答え（ラベル）が既知で攻撃パターンもよく知られた、教育・ベンチマーク用データセットです。ここで良い結果が出るのは「パイプラインのロジックが正しく、実装も正しい」ことの証明であって、「実世界で100%検知できる」という意味では**ありません**。後者はまったく別の、はるかに難しい主張で、このプロジェクトはまだそれを獲得していません。下記参照。

### CICIDS2017で正しく分類できた攻撃種別

| 攻撃種別 | 説明 |
| --- | --- |
| SSH-Patator（偵察） | ポートプローブ・偵察 |
| SSH-Patator（総当たり） | SSH認証総当たり |
| FTP-Patator（即時拒否） | FTP即時拒否型総当たり |
| FTP-Patator（多パケット） | FTP多パケット認証総当たり |
| FTP-Patator（部分接続） | FTP部分接続型総当たり |

---

## 正直な限界

後で気づくより、先に知ってもらう方がいいと思っています。

* **ベンチマーク != 本番。** 現時点の結果は既知のラベル付きデータでのものです。実ネットワークはもっと雑然とノイズが多く、このパイプラインが見たことのない攻撃の変種を含みます。実データでの性能は**未検証**で、ベンチマークより下がります。
* **100%/0%はベンチマークの産物であって、約束ではない。** きれいなラベル付きデータで満点が出るのはよくあることで、それ自体は実用上の信頼性の証拠になりません。「このデータでロジックが動く」以上の意味はありません。
* **入力形式が狭い。** 現状はCICFlowMeter形式のCSVのみ。
* **既知の「ツール挙動の種類」を検知する。** 統計的均一性を根拠にするため、十分に低速・ランダム化され、人間のペースを模した攻撃は回避し得ます。
* **個人開発であり、監査済み製品ではない。** 第三者によるセキュリティレビューは受けていません。

これらのトレードオフが許容できる用途がある方、あるいは - もっと歓迎なのは - 雑然とした実データでのテストを手伝える方がいれば、ぜひご連絡ください。

---

## 出力レポートのサンプル

* [攻撃パターン詳細分析](attack_analysis_report.md) - 各判断の根拠
* [混在データ検知テスト](mixed_classification_report.md) - 正常トラフィック混在下での精度
* [フルスキャンレポート](pipeline_report.md) - 44万行スキャンの実行結果

---

## セットアップ

```bash
git clone https://github.com/YoshiOnGithub/security-pipeline.git
cd security-pipeline
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`.env`ファイルを作成：

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

## 実行方法

```bash
python security_pipeline.py --max-batches 1   # テスト実行（最初の1バッチ）
python security_pipeline.py                    # フルスキャン
python security_pipeline.py --start-batch 100  # チェックポイントから再開
```

## 対応ログ形式

現在：CICFlowMeter形式CSV（ネットワークフローログ）。
今後：Linuxサーバーログ、Windowsイベントログ、AWS CloudTrail、ネットワーク機器ログ。

---

## 開発背景

一つの仮説を検証するために作りました - 「正規トラフィックを装った攻撃者は、パケットを一つずつシグネチャ照合するのではなく、セッションの*文脈*を読むことで捕まえられる」という仮説です。上記のベンチマーク結果は、ラベル付きデータでその仮説を検証した結果です。正直な次のステップは、事前ラベルの付いていないデータでの検証。本当の問いはそこにあります。

## ライセンス

MIT

## 連絡先

IssueとDiscussionを開けています。ネットワークログを扱っていて、これに穴を開けてやろうという方の指摘こそ歓迎です。
