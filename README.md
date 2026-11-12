# cert

複数ホストの TLS 証明書を並列に取得し、発行者・有効期間・SAN に加えて、証明書の種別（Validation: DV / OV / EV）と OV・EV の組織名（Organization）を一覧表示する CLI ツールです。
証明書の期限確認や、DNS 切り替え前の新サーバーの確認に使えます。

## インストール

Rust のツールチェーン（1.88 以上）が必要です。`cert` は `~/.cargo/bin` にインストールされるので、このディレクトリを PATH に含めてください。

### リポジトリから直接インストール

ソースをクローンせずにインストールできます。

```
cargo install --locked \
  --git https://github.com/ytkhs/cert-rs
```

更新するときは、同じコマンドに `--force` を付けて実行します。

### クローンしたソースからインストール

```
cargo install --locked --path .
```

## 使い方

```
cert [OPTIONS] [HOST]...
```

ホストは `example.com`、`example.com:8443`、`https://example.com:8443/path`、`[2001:db8::1]:443` の形式で指定できます。ポートを省略すると 443 を使います。

```
cert example.com example.org
```

### オプション

| オプション | 説明 |
| --- | --- |
| `-f`, `--format <table\|md\|json>` | 出力形式（既定: `table`） |
| `-k`, `--skip-verify` | 証明書チェーンとホスト名の検証を行わない（ハンドシェイクの署名は検証する） |
| `-u`, `--utc` | 日時を UTC で表示する |
| `-s`, `--timeout <秒>` | 接続と TLS ハンドシェイクを合わせたタイムアウト秒数。DNS の名前解決は含まない。0 は上限なし（既定: 3） |
| `-r`, `--resolve <HOST:PORT:ADDR>` | 名前解決を上書きして ADDR に接続する（複数指定可。IPv6 は `[2001:db8::1]` のように角括弧で囲む） |
| `--chain` | サーバーが送ってきた証明書チェーンをそのまま表示し、つながりと有効期間を検査する |
| `-v`, `--version` | バージョンを表示する |

形式を変える:

```
cert -f md example.com
cert -f json example.com
```

期限切れや自己署名の証明書を持つサーバーでも情報を取得する:

```
cert -k example.com
```

UTC で表示し、タイムアウトを 10 秒にする:

```
cert -u -s 10 example.com example.org
```

### --resolve

`--resolve HOST:PORT:ADDR` を指定すると、DNS を引かずに HOST:PORT への接続先を ADDR に固定します。SNI と証明書の検証は HOST に対して行われます。
DNS を切り替える前に、新サーバーが正しい証明書を返しているかを確認する用途を想定しています。

```
cert --resolve example.com:443:192.0.2.10 example.com
```

IPv6 アドレスに向けるときは ADDR を角括弧で囲みます。

```
cert --resolve example.com:443:[2001:db8::1] example.com
```

複数指定もできます。

```
cert -r example.com:443:192.0.2.10 -r example.org:443:192.0.2.11 example.com example.org
```

どのホストとも HOST:PORT が一致しない `--resolve` があると、標準エラー出力に警告を 1 行出します（標準出力は変わりません）。

```
warning: --resolve example.org:443:192.0.2.11 matched no host
```

### --chain

`--chain` を指定すると、サーバーが TLS ハンドシェイクで送ってきた証明書をすべて、送られた順（先頭がサーバー証明書）に表示し、チェーンを検査します。
OS やブラウザは、サーバーが送らなかった中間証明書を自分で補って検証を通すことがあります。cert は通常の実行でも、サーバーが送った証明書だけで検証が通るかを確かめ、送り忘れがあればエラーにします。`--chain` を付けると、送られた証明書の一覧と、つながりや有効期間の検査結果を表示します。証明書を入れ替えたあとの確認に使えます。

```
cert --chain example.com
```

```
DomainName:   example.com
IP:           192.0.2.10
Port:         443
Issuer:       Example Intermediate CA
Validation:   DV
NotBefore:    2026-10-01 09:00:00 +0900 JST
NotAfter:     2027-01-01 08:59:59 +0900 JST
CommonName:   example.com
SANs:         [example.com www.example.com]
Error:        
Chain:
  [0] CN=example.com
      Issuer:    CN=Example Intermediate CA
      NotBefore: 2026-10-01 09:00:00 +0900 JST
      NotAfter:  2027-01-01 08:59:59 +0900 JST
      Serial:    0A1B2C3D
      SHA256:    AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
  [1] CN=Example Intermediate CA
      Issuer:    CN=Example Root CA
      NotBefore: 2025-01-01 09:00:00 +0900 JST
      NotAfter:  2030-01-01 08:59:59 +0900 JST
      Serial:    01
      SHA256:    99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA
ChainCheck:   OK
```

`ChainCheck` は次の 2 点を検査し、`OK` か、見つかった問題をすべて並べた `NG: ...` を表示します。

- 各証明書の発行者が、次の証明書の主体者と一致する（`[0] issuer does not match [1] subject`）。文字列の型や大文字小文字、空白の数だけの違いは一致とみなします
- すべての証明書が現在の時刻で有効期間内にある（`[1] expired`、`[1] not yet valid`）

サーバー証明書 1 枚しか送られず、それが自己署名でもなく、発行者が OS の信頼するルートでもない場合は、中間証明書の送り忘れとして `[0] issuer certificate not sent` を出します。
2 枚以上のときは、末尾の証明書の発行者は検査しません。ルート証明書まで送るサーバーも、ルートを省くサーバーも問題にはなりません。ルートまで信頼できるかどうかは通常の検証（`-k` なし）が担い、`--chain` はその動作を変えません。
解析できない証明書があると `[2] failed to parse certificate: ...` のように位置を示し、ほかの証明書はそのまま表示します。先頭のサーバー証明書が解析できない場合も同じで、`Error` に解析エラーを出し、CN などの欄は空になります。

`-k` を付けなくても使えます。中間証明書の欠落などで検証に失敗した場合も、その接続で受け取ったチェーンを表示し、`Error` には検証に失敗した理由を出します。

NG でも終了コードは 0 のままです。JSON では `chain` と `chainCheck` が各行に加わります。接続できなかった行など、チェーンを読めなかったエラー行にはどちらも付きません。

### JSON と jq

```
cert -f json example.com example.org | jq '.[] | {domainName, notAfter, error}'
```

エラーのあるホストだけを取り出す:

```
cert -f json example.com example.org | jq '.[] | select(.error != "")'
```

## 制限事項

- TLS 1.1 以前、および旧式の暗号スイートのみに対応した TLS 1.2 サーバーには接続できず、エラーになります。
- `-format`、`-skip-verify` のようなハイフン 1 つの長いオプションは使えません。`-f` / `--format`、`-k` / `--skip-verify` のように指定してください。

## 設計判断

主な設計判断は [docs/adr](docs/adr/README.md) に記録しています。

## ライセンス

MIT License。詳細は [LICENSE](LICENSE) を参照。
