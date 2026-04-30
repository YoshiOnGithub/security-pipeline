"""
security_pipeline.py
────────────────────
3-Step Security Analysis Pipeline for CICFlowMeter network flow data.

Step 1 : Rule-based filter — extract attack candidates from Tuesday CSV
Step 2 : Claude AI batch classification (100 sessions / batch)
Step 3 : Generate pipeline_report.md with full statistics

Usage:
    python security_pipeline.py                        # full run
    python security_pipeline.py --dry-run             # Step 1 only (no API calls)
    python security_pipeline.py --max-batches 5       # limit AI batches (for testing)
"""

import os
import sys
import json
import time
import argparse
import textwrap
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import anthropic

# ─────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────
INPUT_CSV       = "Tuesday-WorkingHours.pcap_ISCX.csv"
OUTPUT_MD       = "pipeline_report.md"
CHECKPOINT_FILE = "checkpoint.json"
MODEL           = "claude-haiku-4-5"          # fast & cost-effective for batch work
BATCH_SIZE      = 20    # 20件/バッチ — レスポンスが4096トークンに収まるよう縮小

# ─────────────────────────────────────────────
#  Step 1 — Rule-Based Filter
# ─────────────────────────────────────────────

RULES = [
    {
        "id": "SSH-TypeA",
        "label": "SSH-Patator TypeA（ポートプローブ型）",
        "attack_type": "SSH-Patator",
        "conditions": lambda r: (
            r["Init_Win_bytes_forward"] == 259
            and r["Flow Bytes/s"] == 0.0
            and r["Total Fwd Packets"] == 1
            and r["Total Backward Packets"] == 1
            and r["URG Flag Count"] == 1
        ),
    },
    {
        "id": "SSH-TypeB",
        "label": "SSH-Patator TypeB（認証総当たり型）",
        "attack_type": "SSH-Patator",
        "conditions": lambda r: (
            r["Fwd Packet Length Max"] == 640
            and r["Bwd Packet Length Max"] == 976
        ),
    },
    {
        "id": "SSH-TypeB-aux",
        "label": "SSH-Patator TypeB補助（固定バイト列）",
        "attack_type": "SSH-Patator",
        "conditions": lambda r: (
            r["Total Length of Fwd Packets"] == 2008
            and r["Total Length of Bwd Packets"] == 2745
            and r["Destination Port"] == 22
        ),
    },
    {
        "id": "FTP-TypeA",
        "label": "FTP-Patator TypeA（即時拒否型）",
        "attack_type": "FTP-Patator",
        "conditions": lambda r: (
            r["Init_Win_bytes_backward"] == -1
            and r["Total Backward Packets"] == 0
            and r["Total Length of Fwd Packets"] == 14
            and r["Total Fwd Packets"] == 2
            and r["Destination Port"] == 21
        ),
    },
    {
        "id": "FTP-TypeB",
        "label": "FTP-Patator TypeB（多パケット認証総当たり型）",
        "attack_type": "FTP-Patator",
        "conditions": lambda r: (
            r["Total Length of Bwd Packets"] == 188
            and r["Total Fwd Packets"] == 9
            and r["Total Backward Packets"] == 15
        ),
    },
    {
        "id": "FTP-TypeC",
        "label": "FTP-Patator TypeC（部分接続型）",
        "attack_type": "FTP-Patator",
        "conditions": lambda r: (
            r["Init_Win_bytes_forward"] == 229
            and r["Total Length of Fwd Packets"] == 14
            and r["Total Length of Bwd Packets"] == 0
            and r["Total Fwd Packets"] == 2
            and r["Total Backward Packets"] == 1
        ),
    },
    {
        "id": "FTP-TypeB-aux",
        "label": "FTP-Patator TypeB補助（サーバーウィンドウ固定）",
        "attack_type": "FTP-Patator",
        "conditions": lambda r: (
            r["Init_Win_bytes_backward"] == 227
            and r["Destination Port"] == 21
        ),
    },
]


def apply_rules(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply all rules row-by-row and return a DataFrame of matching candidates.
    Each candidate records which rule first triggered it and the original label (if present).
    """
    print(f"\n[Step 1] ルールベースフィルタ開始 — 対象行数: {len(df):,}")
    t0 = time.time()

    required_cols = [
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "Flow Bytes/s", "Total Fwd Packets", "Total Backward Packets",
        "URG Flag Count", "Fwd Packet Length Max", "Bwd Packet Length Max",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Destination Port",
    ]
    # Fill missing columns with sentinel so rules don't raise KeyError
    for col in required_cols:
        if col not in df.columns:
            print(f"  [警告] 列が見つかりません: '{col}' — 0で補完します")
            df[col] = 0

    # Convert to numeric where needed (CICFlowMeter sometimes outputs strings)
    for col in required_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    matched_indices: dict[int, str] = {}   # index → rule_id (first match wins)
    rule_hit_counts: dict[str, int] = {r["id"]: 0 for r in RULES}

    for rule in RULES:
        rid = rule["id"]
        cond_fn = rule["conditions"]
        mask = df.apply(cond_fn, axis=1)
        new_hits = 0
        for idx in df[mask].index:
            if idx not in matched_indices:
                matched_indices[idx] = rid
                new_hits += 1
        rule_hit_counts[rid] = int(mask.sum())
        print(f"  {rid:15s}: {mask.sum():6,} hits  (新規追加: {new_hits:,})")

    candidates = df.loc[list(matched_indices.keys())].copy()
    candidates["_matched_rule"] = [matched_indices[i] for i in candidates.index]
    candidates = candidates.reset_index(drop=True)

    elapsed = time.time() - t0
    print(f"\n  候補件数: {len(candidates):,} / {len(df):,} 行  ({elapsed:.1f}s)")
    return candidates, rule_hit_counts


# ─────────────────────────────────────────────
#  Step 2 — Claude AI Batch Classification
# ─────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
あなたはネットワークセキュリティの専門家です。
各セッションはすでにルールエンジンが「攻撃の疑いあり」としてフラグを立てたものです。
あなたの役割は、そのフラグを「覆す（benign）」か「維持する（attack/uncertain）」かを判断することです。

## 判断の原則：疑わしきは攻撃とみなす

**benign と判定してよい条件（すべてを満たす場合のみ）:**
1. 攻撃ツールの固有シグネチャが一切見当たらない
2. 正規の通信パターン（ペイロードの変動、自然なウィンドウサイズ、正常なフラグ）が確認できる
3. ルールが誤検知したと断言できる具体的な根拠がある

**上記を満たせない場合は必ず attack または uncertain を選ぶこと。**
「証拠が不十分」「どちらとも言えない」は benign ではなく uncertain です。

## ペイロードゼロに関する重要な判定ルール

**「ペイロードが 0 バイト」は benign の根拠にならない。**

正常な通信失敗（接続拒否・タイムアウト等）では、ペイロードがゼロでも
URG フラグは立たず、TCP ウィンドウサイズは OS の標準値（512/1024/4096 等）になる。

以下の組み合わせが揃っている場合は、通信失敗ではなく
**攻撃ツールによるスキャン・プロービング（偵察活動）と断定せよ：**

- Init_Win_bytes_forward = 259（Patator ライブラリの固定値）
- URG Flag Count = 1（偵察ツール特有。正常通信では URG=1 はほぼ発生しない）
- Flow Bytes/s = 0.0（意図的なペイロードなし接続）

この三点セットは、ツールが意図的に「最小限の痕跡で応答を確認する」偵察パケットを
送信していることを示す。ペイロードがゼロであることは攻撃の否定ではなく、
**むしろ隠蔽を意図した攻撃手法の特徴**である。

## 攻撃シグネチャ（これらが見られる場合は attack）

### SSH-Patator TypeA（ポートプローブ／偵察）
- Init_Win_bytes_forward = 259 **かつ** URG Flag Count = 1 **かつ** Flow Bytes/s = 0.0
- Patatorライブラリ固有のウィンドウサイズ。BENIGNでは観測されない。
- **ペイロードがゼロでも attack と断定すること。ゼロペイロードは偵察の証拠。**

### SSH-Patator TypeB（認証総当たり）
- Fwd Packet Length Max = 640 **かつ** Bwd Packet Length Max = 976
- または Total Length of Fwd = 2008 **かつ** Total Length of Bwd = 2745
- 自動化ツール以外でこの固定バイト列が繰り返されることはない。

### FTP-Patator TypeA（即時拒否・TCPハンドシェイク未完了）
- Init_Win_bytes_backward = -1 **かつ** Total Backward Packets = 0 **かつ** Port = 21
- サーバーがTCPウィンドウを提示していない = 接続未完了。

### FTP-Patator TypeB（認証総当たり）
- Total Length of Bwd Packets = 188（認証失敗応答の固定バイト数）
- Total Fwd Packets = 9, Total Backward Packets = 15 の組み合わせ
- 毎回1バイトも違わない応答は機械的試行の証拠。

### FTP-Patator TypeC（部分接続）
- Init_Win_bytes_forward = 229 **かつ** Total Length of Bwd = 0
- 攻撃ツール固有ウィンドウサイズ。BENIGNには存在しない。

### FTP-Patator TypeB-aux（サーバーウィンドウ固定）
- Init_Win_bytes_backward = 227 **かつ** Port = 21
- 攻撃対象サーバー固有の応答ウィンドウ。

## 判定フロー
1. 上記シグネチャに一致する → **attack**（確信度に応じて high/medium）
2. シグネチャに完全一致しないが類似した異常がある → **uncertain**
3. 攻撃シグネチャが皆無で正常の積極的根拠がある → **benign**（非常にまれなケース）

## 重要
- ルールエンジンはすでにこのセッションを「疑わしい」と判断した。
  その判断を覆す（benign にする）には、攻撃の証拠が存在しないことの明確な説明が必要。
- 「ポート21への接続」「SSH接続」などの事実だけでは benign の根拠にならない。

## 出力形式
必ず以下のJSON配列のみを返すこと（コードブロック・説明文・マークダウン不要）:
[
  {
    "session_id": <整数>,
    "verdict": "attack" | "uncertain" | "benign",
    "attack_type": "SSH-Patator" | "FTP-Patator" | null,
    "confidence": "high" | "medium" | "low",
    "reason": "<40字以内の日本語根拠>"
  },
  ...
]
""").strip()


# rule_id → (label, attack_type, 判定の根拠となった条件の要約)
RULE_CONTEXT: dict = {
    r["id"]: {
        "label":       r["label"],
        "attack_type": r["attack_type"],
    }
    for r in RULES
}


def _sanitize(val: Any) -> Any:
    """
    Convert numpy scalars → Python native, and replace NaN/Inf with None
    so json.dumps always produces valid JSON (no bare NaN/Infinity literals).
    CICFlowMeter columns like 'Flow Bytes/s' are NaN when Flow Duration == 0.
    """
    import math
    if hasattr(val, "item"):          # numpy scalar → Python
        val = val.item()
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return None
    return val


def format_session_for_prompt(idx: int, row: pd.Series, rule_id: str) -> dict:
    """Format a single candidate row as a dict for the AI prompt."""
    feature_keys = [
        "Destination Port", "Flow Duration",
        "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Bwd Packet Length Max",
        "Flow Bytes/s", "Flow Packets/s",
        "URG Flag Count", "FIN Flag Count", "SYN Flag Count",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "Fwd Header Length", "Bwd Header Length",
    ]
    features = {
        k: _sanitize(row[k])
        for k in feature_keys
        if k in row.index
    }

    # ルール合致情報：AIがコンテキストとして参照できるよう明示する
    rc = RULE_CONTEXT.get(rule_id, {"label": rule_id, "attack_type": "不明"})
    rule_alert = {
        "flagged_by_rule":  rule_id,
        "rule_description": rc["label"],
        "suspected_attack": rc["attack_type"],
        "override_note": (
            "このセッションはルールエンジンが攻撃シグネチャと判定した。"
            "benign にするには攻撃シグネチャが存在しない明確な根拠が必要。"
        ),
    }

    return {
        "session_id":  int(idx),     # numpy int64 → Python int（JSON直列化のため）
        "rule_alert":  rule_alert,   # ← 追加：ルール合致コンテキスト
        "features":    features,
    }


# ─────────────────────────────────────────────
#  Checkpoint helpers
# ─────────────────────────────────────────────

def save_checkpoint(
    path: str,
    last_completed_batch: int,
    total_batches: int,
    batch_size: int,
    candidates_count: int,
    verdicts: list,
    token_stats: dict,
) -> None:
    """
    バッチ処理の進捗を JSON ファイルに保存する。
    アトミックな書き込み（tmp → rename）で中途半端なファイルを残さない。
    """
    data = {
        "last_completed_batch": last_completed_batch,
        "total_batches":        total_batches,
        "batch_size":           batch_size,
        "candidates_count":     candidates_count,
        "verdicts":             verdicts,
        "token_stats":          token_stats,
        "saved_at":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)   # atomic on POSIX / Windows


def load_checkpoint(path: str) -> Optional[dict]:
    """checkpoint.json を読み込んで dict を返す。ファイルがなければ None。"""
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────
#  Uncertain Session Deep-Dive
# ─────────────────────────────────────────────

UNCERTAIN_ANALYSIS_PROMPT = textwrap.dedent("""
あなたはネットワークセキュリティの専門家です。
以下のネットワークフローセッションについて、なぜ判定が難しいのかを詳しく分析してください。

このセッションはルールエンジンが「攻撃の疑いあり」としてフラグを立てたものです。
しかし何らかの理由でAIが "uncertain（判断保留）" と判定しました。

## あなたが答えるべきこと
1. **攻撃を疑わせる根拠**: どの特徴量が攻撃のシグネチャに近いか
2. **正常を示唆する根拠**: どの特徴量が正常トラフィックに近いか
3. **判定が難しい本質的な理由**: なぜこのセッションが境界ケースなのか
4. **最終的な推奨判定**: 改めて判断するとしたら attack / uncertain / benign のどれか、その理由

日本語で詳しく（200〜400字程度）記述してください。
""").strip()


def analyze_uncertain_sample(
    client: anthropic.Anthropic,
    uncertain_verdicts: list,
    candidates: pd.DataFrame,
    n_samples: int = 5,
    seed: int = 42,
) -> None:
    """
    uncertain 判定されたセッションからランダムに n_samples 件を抽出し、
    Claude に詳細な思考プロセスを出力させてターミナルに表示する。
    """
    import random
    random.seed(seed)

    if not uncertain_verdicts:
        print("\n[Uncertain分析] uncertain 判定のセッションがありません。")
        return

    sample = random.sample(uncertain_verdicts, min(n_samples, len(uncertain_verdicts)))
    print(f"\n{'='*60}")
    print(f"  Uncertain セッション 詳細分析（{len(sample)}件サンプル）")
    print(f"{'='*60}")

    for i, v in enumerate(sample, 1):
        sid = v["session_id"]
        rule_id = candidates.iloc[sid]["_matched_rule"] if sid < len(candidates) else "不明"
        actual_label = candidates.iloc[sid]["Label"] if (sid < len(candidates) and "Label" in candidates.columns) else "不明"

        session_data = format_session_for_prompt(sid, candidates.iloc[sid], rule_id) if sid < len(candidates) else {}
        session_json = json.dumps(session_data, ensure_ascii=False, indent=2, allow_nan=False)

        print(f"\n{'─'*60}")
        print(f"  サンプル {i}/{len(sample)}  session_id={sid}  rule={rule_id}  実ラベル={actual_label}")
        print(f"{'─'*60}")

        user_msg = f"以下のセッションを分析してください。\n\n```json\n{session_json}\n```"
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=UNCERTAIN_ANALYSIS_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            analysis = resp.content[0].text.strip()
            print(analysis)
            print(f"\n  [トークン] in={resp.usage.input_tokens} out={resp.usage.output_tokens}")
        except Exception as e:
            print(f"  [エラー] {type(e).__name__}: {e}")


def _extract_json_array(text: str) -> list:
    """
    Robustly extract a JSON array from Claude's response text.
    Handles:
      - Bare JSON array (ideal case)
      - JSON wrapped in ```json ... ``` or ``` ... ``` code fences
      - Explanatory text before/after the JSON array
    """
    import re
    text = text.strip()

    # 1. Try to parse as-is first (fastest path)
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # 2. Strip code fences and try again
    # Handles: ```json\n[...]\n``` or ```\n[...]\n```
    fence_pattern = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.DOTALL)
    for m in fence_pattern.finditer(text):
        candidate = m.group(1).strip()
        try:
            result = json.loads(candidate)
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            continue

    # 3. Find the first '[' ... last ']' span (handles preamble/postamble text)
    start = text.find("[")
    end   = text.rfind("]")
    if start != -1 and end > start:
        candidate = text[start:end + 1]
        try:
            result = json.loads(candidate)
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    # 4. Nothing worked — raise so the caller can log the raw text
    raise ValueError(f"JSON array not found in response (first 200 chars): {text[:200]!r}")


def classify_batch(
    client: anthropic.Anthropic,
    batch: list,
    batch_num: int,
    total_batches: int,
) -> tuple:
    """
    Send one batch of sessions to Claude and return verdicts.
    Falls back to 'uncertain' entries on any error.
    """
    # Build user message — json.dumps with allow_nan=False ensures valid JSON
    # (_sanitize already replaced NaN/Inf with None, so this should never raise)
    sessions_json = json.dumps(batch, ensure_ascii=False, indent=2, allow_nan=False)
    user_message = (
        f"以下の {len(batch)} セッションを判定してください。\n\n"
        f"```json\n{sessions_json}\n```"
    )

    def _fallback(reason: str) -> tuple:
        entries = [
            {"session_id": s["session_id"], "verdict": "uncertain",
             "attack_type": None, "confidence": "low", "reason": reason}
            for s in batch
        ]
        return entries, 0, 0, 0, 0

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8192,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        )

        # Extract token counts BEFORE parsing so they're always available
        input_tokens  = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        cache_read    = getattr(response.usage, "cache_read_input_tokens", 0) or 0
        cache_create  = getattr(response.usage, "cache_creation_input_tokens", 0) or 0

        raw_text = response.content[0].text.strip()

        # デバッグ: 実際のレスポンス先頭500文字を表示
        print(f"  [DEBUG raw_text Batch {batch_num}] {raw_text[:500]!r}")

        try:
            verdicts = _extract_json_array(raw_text)
        except (ValueError, json.JSONDecodeError) as parse_err:
            print(f"  [警告] Batch {batch_num}: JSONパースエラー — {parse_err}")
            print(f"          raw (200): {raw_text[:200]!r}")
            # Return fallback BUT keep real token counts so billing is accurate
            entries = [
                {"session_id": s["session_id"], "verdict": "uncertain",
                 "attack_type": None, "confidence": "low", "reason": "JSONパースエラー"}
                for s in batch
            ]
            return entries, input_tokens, output_tokens, cache_read, cache_create

        print(
            f"  Batch {batch_num:4d}/{total_batches}  "
            f"sessions={len(batch):3d}  verdicts={len(verdicts):3d}  "
            f"in={input_tokens:5d} out={output_tokens:4d}  "
            f"cache_read={cache_read:5d} cache_create={cache_create:5d}"
        )
        return verdicts, input_tokens, output_tokens, cache_read, cache_create

    except anthropic.APIStatusError as e:
        print(f"  [エラー] Batch {batch_num}: API ステータスエラー {e.status_code} — {e.message}")
        return _fallback(f"APIエラー {e.status_code}")

    except anthropic.APIConnectionError as e:
        print(f"  [エラー] Batch {batch_num}: 接続エラー — {e}")
        return _fallback("接続エラー")

    except Exception as e:
        # Catch-all: log the full exception so nothing is silently swallowed
        print(f"  [エラー] Batch {batch_num}: 予期しないエラー {type(e).__name__} — {e}")
        return _fallback(f"{type(e).__name__}")


def run_ai_classification(
    candidates: pd.DataFrame,
    max_batches: Optional[int] = None,
    start_batch: int = 1,
    checkpoint_path: str = CHECKPOINT_FILE,
) -> tuple:
    """
    Step 2: Claude API によるバッチ分類。

    start_batch  : 再開開始バッチ番号（1始まり）。
                   1 より大きい場合は checkpoint_path から既存結果を読み込む。
    checkpoint_path: 進捗を逐次保存する JSON ファイルパス。
                     バッチ完了ごとに上書きされる。
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n[Step 2] ANTHROPIC_API_KEY が設定されていません。Step 2 をスキップします。")
        return [], {}

    client = anthropic.Anthropic(api_key=api_key)

    # ── 全バッチリストを構築 ────────────────────────────────────────────────
    sessions = [
        format_session_for_prompt(i, candidates.iloc[i], candidates.iloc[i]["_matched_rule"])
        for i in range(len(candidates))
    ]
    all_batches   = [sessions[i:i + BATCH_SIZE] for i in range(0, len(sessions), BATCH_SIZE)]
    total_batches = len(all_batches)

    # ── チェックポイント読み込み（resume 時）──────────────────────────────
    prior_verdicts: list  = []
    prior_token_stats: dict = {
        "total_input_tokens": 0, "total_output_tokens": 0,
        "total_cache_read_tokens": 0, "total_cache_creation_tokens": 0,
        "elapsed_seconds": 0.0, "batches_processed": 0, "sessions_sent": 0,
    }

    if start_batch > 1:
        cp = load_checkpoint(checkpoint_path)
        if cp is None:
            print(f"  [エラー] --start-batch {start_batch} が指定されましたが "
                  f"'{checkpoint_path}' が見つかりません。フルランを実行してください。")
            sys.exit(1)

        # 整合性チェック
        if cp["last_completed_batch"] != start_batch - 1:
            print(f"  [エラー] チェックポイントの last_completed_batch={cp['last_completed_batch']} と "
                  f"--start-batch {start_batch} が一致しません（期待値: {start_batch - 1}）。")
            sys.exit(1)
        if cp["batch_size"] != BATCH_SIZE:
            print(f"  [警告] チェックポイントの batch_size={cp['batch_size']} が "
                  f"現在の BATCH_SIZE={BATCH_SIZE} と異なります。続行します。")
        if cp["candidates_count"] != len(candidates):
            print(f"  [エラー] チェックポイントの candidates_count={cp['candidates_count']} が "
                  f"現在の候補数 {len(candidates)} と異なります。Step 1 結果が変わっています。")
            sys.exit(1)

        prior_verdicts    = cp["verdicts"]
        prior_token_stats = cp["token_stats"]
        print(f"\n[Step 2] チェックポイント読み込み完了 — "
              f"バッチ {cp['last_completed_batch']}/{total_batches} まで処理済み "
              f"({len(prior_verdicts):,} 件, 保存日時: {cp['saved_at']})")

    # ── 処理範囲を決定 ────────────────────────────────────────────────────
    # start_batch は 1 始まりなので index は start_batch-1
    end_batch = total_batches
    if max_batches is not None:
        end_batch = min(start_batch - 1 + max_batches, total_batches)

    batches_to_run = all_batches[start_batch - 1:end_batch]

    if not batches_to_run:
        print("\n[Step 2] 処理対象バッチなし（既に全バッチ完了済み）。")
        return prior_verdicts, prior_token_stats

    run_desc = f"バッチ {start_batch}〜{end_batch} / {total_batches}"
    if max_batches is not None:
        run_desc += f"  (--max-batches {max_batches} により上限あり)"
    print(f"\n[Step 2] AI分類開始 — {run_desc}  × 最大 {BATCH_SIZE} 件/バッチ")

    # ── バッチループ ──────────────────────────────────────────────────────
    all_verdicts = list(prior_verdicts)   # 既存分をコピーして積み上げる
    total_in          = prior_token_stats.get("total_input_tokens", 0)
    total_out         = prior_token_stats.get("total_output_tokens", 0)
    total_cache_read  = prior_token_stats.get("total_cache_read_tokens", 0)
    total_cache_create = prior_token_stats.get("total_cache_creation_tokens", 0)
    t0 = time.time()

    for rel_idx, batch in enumerate(batches_to_run):
        batch_num = start_batch + rel_idx   # 絶対バッチ番号（表示・チェックポイント用）

        verdicts, inp, out, cr, cc = classify_batch(
            client, batch, batch_num, total_batches
        )
        all_verdicts.extend(verdicts)
        total_in           += inp
        total_out          += out
        total_cache_read   += cr
        total_cache_create += cc

        # バッチ完了ごとにチェックポイントを更新
        current_token_stats = {
            "total_input_tokens":          total_in,
            "total_output_tokens":         total_out,
            "total_cache_read_tokens":     total_cache_read,
            "total_cache_creation_tokens": total_cache_create,
            "elapsed_seconds":             round(time.time() - t0 + prior_token_stats.get("elapsed_seconds", 0), 1),
            "batches_processed":           batch_num,
            "sessions_sent":               len(all_verdicts),
        }
        save_checkpoint(
            path                 = checkpoint_path,
            last_completed_batch = batch_num,
            total_batches        = total_batches,
            batch_size           = BATCH_SIZE,
            candidates_count     = len(candidates),
            verdicts             = all_verdicts,
            token_stats          = current_token_stats,
        )

        # レート制限への配慮
        if rel_idx < len(batches_to_run) - 1:
            time.sleep(0.3)

    elapsed_new = time.time() - t0
    total_elapsed = elapsed_new + prior_token_stats.get("elapsed_seconds", 0.0)

    final_token_stats = {
        "total_input_tokens":          total_in,
        "total_output_tokens":         total_out,
        "total_cache_read_tokens":     total_cache_read,
        "total_cache_creation_tokens": total_cache_create,
        "elapsed_seconds":             round(total_elapsed, 1),
        "batches_processed":           end_batch,
        "sessions_sent":               len(all_verdicts),
    }

    # 全バッチ完了したらチェックポイントを削除
    if end_batch == total_batches and max_batches is None:
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
            print(f"  [チェックポイント] 全バッチ完了 — '{checkpoint_path}' を削除しました。")

    print(f"\n  AI分類完了  今回: {elapsed_new:.1f}s  累計: {total_elapsed:.1f}s  "
          f"total_in={total_in:,}  total_out={total_out:,}  "
          f"cache_read={total_cache_read:,}")
    return all_verdicts, final_token_stats


# ─────────────────────────────────────────────
#  Step 3 — Report Generation
# ─────────────────────────────────────────────

def build_report(
    total_rows: int,
    candidates: pd.DataFrame,
    rule_hit_counts: dict[str, int],
    all_verdicts: list[dict],
    token_stats: dict,
    pipeline_start: float,
    max_batches: Optional[int],
    dry_run: bool,
) -> str:
    """Compose the full markdown report string."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pipeline_elapsed = round(time.time() - pipeline_start, 1)

    # ── Verdict tallies ──────────────────────────────────────────────────────
    ai_attack   = sum(1 for v in all_verdicts if v.get("verdict") == "attack")
    ai_benign   = sum(1 for v in all_verdicts if v.get("verdict") == "benign")
    ai_uncertain = sum(1 for v in all_verdicts if v.get("verdict") == "uncertain")

    attack_types: dict[str, int] = {}
    for v in all_verdicts:
        if v.get("verdict") == "attack" and v.get("attack_type"):
            t = v["attack_type"]
            attack_types[t] = attack_types.get(t, 0) + 1

    # ── Candidate label breakdown (if Label column exists) ──────────────────
    has_label = "Label" in candidates.columns
    if has_label:
        label_counts = candidates["Label"].value_counts().to_dict()
        true_attacks_in_candidates = sum(
            v for k, v in label_counts.items() if k != "BENIGN"
        )
        fp_in_candidates = label_counts.get("BENIGN", 0)
    else:
        label_counts = {}
        true_attacks_in_candidates = fp_in_candidates = "N/A"

    # ── Build markdown ───────────────────────────────────────────────────────
    lines = []

    lines.append("# セキュリティパイプライン 実行レポート")
    lines.append(f"> **実行日時**: {now}  ")
    lines.append(f"> **対象ファイル**: `{INPUT_CSV}`  ")
    lines.append(f"> **AIモデル**: `{MODEL}`  ")
    lines.append(f"> **総処理時間**: {pipeline_elapsed}s\n")

    lines.append("---\n")

    # ── Executive Summary ────────────────────────────────────────────────────
    lines.append("## エグゼクティブサマリー\n")
    lines.append("| 項目 | 値 |")
    lines.append("|------|-----|")
    lines.append(f"| スキャン対象行数 | **{total_rows:,}** 行 |")
    lines.append(f"| ルール抽出候補数 | **{len(candidates):,}** 件 ({len(candidates)/total_rows*100:.2f}%) |")
    if not dry_run:
        ai_processed   = len(all_verdicts)
        batches_done   = token_stats.get("batches_processed", 0)
        total_b        = token_stats.get("total_batches_hint", "?")
        lines.append(f"| AI判定件数 | **{ai_processed:,}** 件 |")
        lines.append(f"| AI確定攻撃 | **{ai_attack:,}** 件 |")
        lines.append(f"| AI確定正常 (誤検知除外) | **{ai_benign:,}** 件 |")
        lines.append(f"| AI不確定 | **{ai_uncertain:,}** 件 |")
        lines.append(f"| 処理済みバッチ | {batches_done:,} |")
    else:
        lines.append("| AI判定 | ドライランのためスキップ |")
    lines.append(f"| 総処理時間 | {pipeline_elapsed}s |")
    lines.append("")

    # ── Step 1 Detail ────────────────────────────────────────────────────────
    lines.append("---\n")
    lines.append("## Step 1 — ルールベースフィルタ結果\n")
    lines.append("### ルール別ヒット数\n")
    lines.append("| ルールID | 説明 | 総ヒット数 |")
    lines.append("|----------|------|-----------|")
    for rule in RULES:
        rid = rule["id"]
        count = rule_hit_counts.get(rid, 0)
        lines.append(f"| `{rid}` | {rule['label']} | {count:,} 件 |")
    lines.append(f"\n> ルール間の重複を除いた**ユニーク候補数**: **{len(candidates):,}** 件\n")

    if has_label:
        lines.append("### 候補のラベル内訳（検証用）\n")
        lines.append("| ラベル | 件数 |")
        lines.append("|--------|------|")
        for label, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {label} | {cnt:,} |")
        lines.append(f"\n> ルールによる**誤検知 (BENIGN)**: {fp_in_candidates:,} 件  \n"
                     f"> ルールに引っかかった**真の攻撃**: {true_attacks_in_candidates:,} 件\n")

    # ── Step 2 Detail ────────────────────────────────────────────────────────
    lines.append("---\n")
    lines.append("## Step 2 — AI バッチ分類結果\n")

    if dry_run:
        lines.append("> **ドライランモード**: `--dry-run` フラグにより AI 分類をスキップしました。\n")
    elif not all_verdicts:
        lines.append("> **スキップ**: `ANTHROPIC_API_KEY` が未設定のため AI 分類を実行できませんでした。\n")
    else:
        partial = max_batches is not None or token_stats.get("batches_processed", 0) < token_stats.get("total_batches_hint", 0)
        if partial and max_batches is not None:
            lines.append(f"> **注意**: `--max-batches {max_batches}` により {token_stats.get('batches_processed', '?')} バッチ ({len(all_verdicts):,} 件) のみ処理しました。続きは `--start-batch {token_stats.get('batches_processed', 0) + 1}` で再開できます。\n")

        lines.append("### AI判定サマリー\n")
        lines.append("| 判定 | 件数 | 割合 |")
        lines.append("|------|------|------|")
        total_v = len(all_verdicts) or 1
        lines.append(f"| 攻撃 (attack) | **{ai_attack:,}** | {ai_attack/total_v*100:.1f}% |")
        lines.append(f"| 正常 (benign) | {ai_benign:,} | {ai_benign/total_v*100:.1f}% |")
        lines.append(f"| 不確定 (uncertain) | {ai_uncertain:,} | {ai_uncertain/total_v*100:.1f}% |")
        lines.append(f"| **合計** | **{total_v:,}** | 100% |")
        lines.append("")

        if attack_types:
            lines.append("### 攻撃タイプ別内訳\n")
            lines.append("| 攻撃タイプ | 件数 |")
            lines.append("|------------|------|")
            for atype, cnt in sorted(attack_types.items(), key=lambda x: -x[1]):
                lines.append(f"| {atype} | {cnt:,} |")
            lines.append("")

        # Token usage
        lines.append("### トークン使用量\n")
        lines.append("| 項目 | 値 |")
        lines.append("|------|-----|")
        lines.append(f"| 処理バッチ数 | {token_stats.get('batches_processed', 0):,} |")
        lines.append(f"| AI処理件数 | {token_stats.get('sessions_sent', 0):,} |")
        lines.append(f"| 入力トークン | {token_stats.get('total_input_tokens', 0):,} |")
        lines.append(f"| 出力トークン | {token_stats.get('total_output_tokens', 0):,} |")
        lines.append(f"| キャッシュ読み込みトークン | {token_stats.get('total_cache_read_tokens', 0):,} |")
        lines.append(f"| キャッシュ作成トークン | {token_stats.get('total_cache_creation_tokens', 0):,} |")
        lines.append(f"| AI処理時間 | {token_stats.get('elapsed_seconds', 0):.1f}s |")
        lines.append("")

    # ── Step 3 / Conclusion ──────────────────────────────────────────────────
    lines.append("---\n")
    lines.append("## Step 3 — 結論と推奨アクション\n")

    if not dry_run and all_verdicts:
        detection_rate = ai_attack / (len(all_verdicts) or 1) * 100
        lines.append(f"- ルール + AI の 2 段階フィルタにより、445,909 行から **{ai_attack:,} 件** の攻撃セッションを特定。")
        lines.append(f"- AI が誤検知として除外した候補: **{ai_benign:,} 件**（ルール単独では誤検知していた BENIGN セッション）")
        lines.append(f"- 不確定セッション {ai_uncertain:,} 件は手動レビューを推奨。")
        lines.append("")
        lines.append("### 推奨アクション")
        lines.append("1. **即時対応**: `attack` 判定セッションの送信元 IP をファイアウォールでブロック")
        lines.append("2. **調査**: `uncertain` セッションをセキュリティアナリストが個別確認")
        lines.append("3. **モニタリング強化**: FTP(21) / SSH(22) ポートへの接続レートを監視")
        lines.append("4. **ログ保全**: 攻撃セッションに関連するフローデータを証跡として保存")
    else:
        lines.append("- AI 分類が未実行のため、最終確定件数は未算出。")
        lines.append("- `ANTHROPIC_API_KEY` を設定して再実行してください。")
        lines.append(f"- ルールフィルタは正常動作済み（候補 {len(candidates):,} 件を抽出）。")

    lines.append("")
    lines.append("---")
    lines.append(f"\n*レポート生成: `security_pipeline.py`  |  {now}*")

    return "\n".join(lines)


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="3-Step Security Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            使用例:
              python security_pipeline.py                        # フル実行
              python security_pipeline.py --dry-run             # Step 1 のみ
              python security_pipeline.py --max-batches 5       # 先頭 5 バッチだけ
              python security_pipeline.py --start-batch 289     # 288 バッチ目まで処理済みで再開
        """),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Step 1 のみ実行（AI API 呼び出しなし）"
    )
    parser.add_argument(
        "--max-batches", type=int, default=None, metavar="N",
        help="AI バッチ数の上限（テスト用）"
    )
    parser.add_argument(
        "--start-batch", type=int, default=1, metavar="N",
        help="再開バッチ番号（1始まり）。N-1 バッチ目までの結果を --checkpoint から読み込む。"
    )
    parser.add_argument(
        "--checkpoint", default=CHECKPOINT_FILE, metavar="FILE",
        help=f"チェックポイントファイルパス (デフォルト: {CHECKPOINT_FILE})"
    )
    parser.add_argument(
        "--analyze-uncertain", action="store_true",
        help="AI分類後、uncertain判定セッションから5件をサンプリングして詳細分析を表示する"
    )
    parser.add_argument(
        "--input", default=INPUT_CSV,
        help=f"入力 CSV ファイル (デフォルト: {INPUT_CSV})"
    )
    parser.add_argument(
        "--output", default=OUTPUT_MD,
        help=f"出力レポートファイル (デフォルト: {OUTPUT_MD})"
    )
    args = parser.parse_args()

    if args.start_batch < 1:
        parser.error("--start-batch は 1 以上の整数を指定してください。")

    pipeline_start = time.time()
    print("=" * 60)
    print("  Security Pipeline — 3-Step Attack Detection")
    print("=" * 60)

    # ── Load CSV ─────────────────────────────────────────────────────────────
    print(f"\n[Load] {args.input} を読み込み中...")
    if not os.path.exists(args.input):
        print(f"[エラー] ファイルが見つかりません: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)
    df.columns = df.columns.str.strip()
    total_rows = len(df)
    print(f"  読み込み完了: {total_rows:,} 行 × {len(df.columns)} 列")

    # ── Step 1 ───────────────────────────────────────────────────────────────
    candidates, rule_hit_counts = apply_rules(df)

    if args.dry_run:
        print("\n[Step 2] --dry-run が指定されているため AI 分類をスキップします。")
        all_verdicts = []
        token_stats = {}
    else:
        # ── Step 2 ───────────────────────────────────────────────────────────
        all_verdicts, token_stats = run_ai_classification(
            candidates,
            max_batches     = args.max_batches,
            start_batch     = args.start_batch,
            checkpoint_path = args.checkpoint,
        )

        # ── Uncertain サンプリング分析（オプション）────────────────────────
        if args.analyze_uncertain and all_verdicts:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                uncertain_verdicts = [v for v in all_verdicts if v.get("verdict") == "uncertain"]
                analyze_uncertain_sample(
                    client            = anthropic.Anthropic(api_key=api_key),
                    uncertain_verdicts = uncertain_verdicts,
                    candidates        = candidates,
                )
            else:
                print("\n[Uncertain分析] ANTHROPIC_API_KEY 未設定のためスキップ。")

    # ── Step 3 ───────────────────────────────────────────────────────────────
    print(f"\n[Step 3] レポート生成中 → {args.output}")
    report_md = build_report(
        total_rows      = total_rows,
        candidates      = candidates,
        rule_hit_counts = rule_hit_counts,
        all_verdicts    = all_verdicts,
        token_stats     = token_stats,
        pipeline_start  = pipeline_start,
        max_batches     = args.max_batches,
        dry_run         = args.dry_run,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"  {args.output} を保存しました。")
    print(f"\n{'='*60}")
    print(f"  パイプライン完了  総処理時間: {time.time()-pipeline_start:.1f}s")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
