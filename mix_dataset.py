# mix_dataset.py
import pandas as pd

# MondayのBENIGNデータを50件取得
monday = pd.read_csv("Monday-WorkingHours.pcap_ISCX.csv")
monday.columns = monday.columns.str.strip()
benign = monday[monday["Label"] == "BENIGN"].sample(50, random_state=42)

# 昨日の攻撃100件を読み込み
attacks = pd.read_csv("attack_sample_100.csv")

# 混在データセットを作成（ラベルは隠さない）
mixed = pd.concat([benign, attacks]).sample(frac=1, random_state=42).reset_index(drop=True)
mixed.to_csv("mixed_150.csv", index=False)

print(f"正常: {len(benign)}件")
print(f"攻撃: {len(attacks)}件")
print(f"合計: {len(mixed)}件")
print("mixed_150.csv を保存しました")