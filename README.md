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

ホストは `example.com`、`example.com:8443`、`https://example.com:8443/path`、`[2001:db8::1]:443` の形式で指定できます。ポートを省略すると 443 を使います。`http://` の URL でポートを省略すると、URL のとおり 80 番に接続します。80 番は普通 TLS で応答しないのでエラーになり、`https://` かホスト名だけで指定し直すよう案内を出します。

```
cert example.com example.org
```

### オプション

| オプション | 説明 |
| --- | --- |
| `-f`, `--format <table\|md\|json>` | 出力形式（既定: `table`）。table と md には期限までの日数（DaysLeft）も出る |
| `-k`, `--skip-verify` | 証明書チェーンとホスト名の検証を行わない（ハンドシェイクの署名は検証する） |
| `-u`, `--utc` | 日時を UTC で表示する |
| `-s`, `--timeout <秒>` | 接続と TLS ハンドシェイクを合わせたタイムアウト秒数。DNS の名前解決は含まない。0 は上限なし（既定: 10） |
| `-r`, `--resolve <HOST:PORT:ADDR>` | 名前解決を上書きして ADDR に接続する（複数指定可。IPv6 は `[2001:db8::1]` のように角括弧で囲む） |
| `--chain` | サーバーが送ってきた証明書チェーンをそのまま表示し、つながりと有効期間を検査する |
| `--fail` | エラーかチェーンの問題があるホストが 1 つでもあれば、終了コード 1 で終わる（出力は変わらない） |
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
DaysLeft:     49
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

NG でも終了コードは 0 のままです。JSON では `chain`・`chainCheck`・`chainProblems` が各行に加わります。接続できなかった行など、チェーンを読めなかったエラー行にはどちらも付きません。

### JSON と jq

```
cert -f json example.com example.org | jq '.[] | {domainName, notAfter, error}'
```

エラーのあるホストだけを取り出す:

```
cert -f json example.com example.org | jq '.[] | select(.errorKind != null)'
```

30 日以内に期限が切れるホストを取り出す:

```
cert -f json example.com example.org | jq '.[] | select(.daysLeft != null and .daysLeft < 30)'
```

スクリプトや CI で失敗を検出する:

```
cert --fail example.com example.org
```

#### JSON の欄

スクリプトや AI から読むときは、表示用の `notBefore`・`notAfter`・`error` ではなく、次の欄を使ってください。表示用の欄は文言や書式が変わることがありますが、これらの欄の値は変えません。

| 欄 | 内容 |
| --- | --- |
| `notBeforeUtc`, `notAfterUtc` | 有効期間の始まりと終わり。RFC 3339 の UTC（例: `2027-01-01T00:00:00Z`）。エラー行は `null` |
| `daysLeft` | 期限までの日数（切り捨て）。期限切れなら負の数。エラー行は `null` |
| `errorKind` | エラーの種類。エラーがなければ `null`。値は下の表のとおり |
| `chainProblems` | `--chain` のときだけ付く。チェーンの問題の配列で、問題がなければ `[]`。各要素は `index`（何番目の証明書か）、`kind`、`message` |
| `chain[].notBeforeUtc`, `chain[].notAfterUtc` | チェーンの各証明書の有効期間（RFC 3339 の UTC） |
| `tlsVersion` | 合意した TLS のバージョン（`TLSv1.3`、`TLSv1.2`）。接続できなかった行は `null` |
| `cipherSuite` | 合意した暗号方式の IANA 名（例: `TLS13_AES_128_GCM_SHA256`） |
| `keyType`, `keyBits`, `curve` | サーバー証明書の鍵の種類（`RSA`、`EC`、`Ed25519`、`Ed448`、`DSA`）と長さ。`curve` は EC のときだけ（例: `P-256`） |
| `signatureAlgorithm` | サーバー証明書の署名方式。OpenSSL と同じ名前（例: `sha256WithRSAEncryption`、`ecdsa-with-SHA256`） |

エラー行でも、`port` と、接続できた場合は `ip` が入ります。時間切れのエラー文には、`-s` で制限時間を延ばせることを添えます。

`errorKind` の値:

| 値 | 意味 |
| --- | --- |
| `invalid_input` | ホストの指定が不正 |
| `dns` | 名前解決に失敗した |
| `connect` | 接続を拒否された、または到達できない |
| `timeout` | 接続かハンドシェイクが時間切れになった |
| `not_tls` | TLS で応答しないポート |
| `handshake_refused` | サーバーがハンドシェイクを拒否した（TLS 1.1 以前や古い暗号方式のみのサーバー） |
| `handshake_failed` | そのほかの TLS の失敗 |
| `expired`, `not_yet_valid` | サーバー証明書が有効期間外 |
| `name_mismatch` | 証明書がホスト名に合わない |
| `untrusted` | 信頼できるルートにつながらない |
| `revoked` | 失効している |
| `weak_signature` | SHA-1 など危険な署名方式 |
| `missing_intermediate` | サーバーが中間証明書を送っていない |
| `sent_intermediate_out_of_date` | サーバーが送った中間証明書が有効期間外 |
| `certificate_invalid` | そのほかの証明書の問題 |
| `parse_error` | 証明書を解析できない |
| `internal` | cert 自身の内部エラー |

`chainProblems[].kind` の値: `issuer_mismatch`（`index` の証明書の発行者が次の証明書と一致しない）、`expired`、`not_yet_valid`、`issuer_not_sent`、`parse_error`、`invalid_time`。

## 制限事項

- TLS 1.1 以前、および旧式の暗号スイートのみに対応した TLS 1.2 サーバーには接続できず、エラーになります。
- `-format`、`-skip-verify` のようなハイフン 1 つの長いオプションは使えません。`-f` / `--format`、`-k` / `--skip-verify` のように指定してください。

## 設計判断

主な設計判断は [docs/adr](docs/adr/README.md) に記録しています。

## ライセンス

MIT License。詳細は [LICENSE](LICENSE) を参照。
