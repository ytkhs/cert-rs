# 0006. DV/OV/EV の判定方法

- ステータス: 承認
- 日付: 2026-11-07

## 背景

証明書の入れ替え前後で、認証の種類（DV/OV/EV）と組織名が想定どおりかを確認したい。発行者名から推測すると、同じ CA が DV と OV の両方を出している場合に誤る。

## 決定

サーバー証明書（チェーンの先頭）を、次の順に判定する。

1. EV: CA/Browser Forum の EV ポリシー OID `2.23.140.1.1` を持つ。持たない場合でも、subject に O があり、businessCategory・serialNumber・jurisdiction（Country / State / Locality のいずれか）がそろっていれば EV
2. OV: ポリシー OID `2.23.140.1.2.2`
3. DV: ポリシー OID `2.23.140.1.2.1`
4. どれもなければ、subject に O があれば OV、なければ DV

組織名（O）は OV と EV のときだけ表示する。CN・発行者の CN・O は、UTF8String などに加えて、T61String（Latin-1 として）と BMPString（UTF-16BE として）も読む。O の有無の判定と表示する値は、同じ読み方で得た結果を使う。

## 結果

- 発行者名に左右されずに判定できる。
- 古い証明書の CN や O が空欄になることを防げる。
