# Architecture Decision Records

このディレクトリには、cert の設計判断を 1 件 1 ファイルで記録しています。

| 番号 | タイトル | ステータス |
|---|---|---|
| [0001](0001-use-rustls.md) | TLS ライブラリに rustls を使う | 承認 |
| [0002](0002-skip-verify-scope.md) | `-k` で省略する検証の範囲 | 承認 |
| [0003](0003-timeout-as-overall-deadline.md) | `-s` を接続全体の締め切りにする | 承認 |
| [0004](0004-threads-without-async-runtime.md) | 並列処理は非同期ランタイムを使わずスレッドで行う | 承認 |
| [0005](0005-resolve-option.md) | `--resolve` で接続先を差し替える | 承認 |
| [0006](0006-validation-type-detection.md) | DV/OV/EV の判定方法 | 承認 |
| [0007](0007-output-and-exit-code.md) | 出力形式と終了コード | 承認 |
| [0008](0008-chain-check.md) | `--chain` でサーバーが送った証明書チェーンを検査する | 一部を 0009 で置き換え |
| [0009](0009-chain-check-revisions.md) | `--chain` の見直し（検証失敗時の表示・欠落の検出・名前の比較・解析失敗・シリアル番号） | 承認 |

新しい判断を記録するときは、次の番号でファイルを追加し、上の表に行を足してください。決定を覆すときは元の ADR を書き換えず、新しい ADR を追加して元のステータスを「〜で置き換え」に変えます。

## テンプレート

```markdown
# NNNN. タイトル

- ステータス: 提案 | 承認 | 〜で置き換え
- 日付: YYYY-MM-DD

## 背景

## 決定

## 結果
```
