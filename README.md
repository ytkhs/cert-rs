# cert

複数ホストの TLS 証明書を並列に取得し、発行者・有効期間・SAN に加えて、証明書の種別（Validation: DV / OV / EV）と OV・EV の組織名（Organization）を一覧表示する CLI ツールです。
証明書の期限確認や、DNS 切り替え前の新サーバーの確認に使えます。

## インストール

Rust のツールチェーンが必要です。

```
cargo install --path .
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
