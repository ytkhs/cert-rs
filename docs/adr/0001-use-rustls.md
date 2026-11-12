# 0001. TLS ライブラリに rustls を使う

- ステータス: 承認（検証方法の一部を [0010](0010-require-sent-chain.md) で補足）
- 日付: 2026-11-07

## 背景

cert はサーバーに TLS で接続して証明書を取り出す。Rust で使える TLS ライブラリには主に rustls、native-tls（OS の TLS 実装）、openssl クレートがある。

## 決定

rustls を使う。暗号プロバイダは ring を明示的に指定し、証明書の信頼には rustls-platform-verifier を通して OS のトラストストアを使う。OpenSSL や native-tls へのフォールバックは作らない。

## 結果

- 純粋な Rust でビルドでき、OpenSSL のバージョンや配置に左右されない。aws-lc-rs ではなく ring を選んだので、ビルドに cmake も要らない。
- TLS 1.1 以前のサーバーや、TLS 1.2 でも CBC のみ・RSA 鍵交換のみ・SHA-1 署名のみのサーバーには接続できない。ハンドシェイクの失敗として Error 欄に出る。
- 暗号スイートを指定して接続するオプションは提供できない。
