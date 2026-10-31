# SBCL 版から ECL 版への移植メモ

SBCL 版 (`4189ef3`) を ECL 21.2.1 向けに書き換えた。**SBCL との互換は持たない** (ECL 専用)。

## 方針

- OS 依存の呼び出しは `src/posix.lisp` に集め、他のファイルは `os-*` / `proc-*` 関数だけを使う。
- ECL は `compile-file` が C 経由なので、`ffi:clines` / `ffi:c-inline` で libc を直接呼ぶ。
  そのため **gcc と libecl-dev が必要**。`c-inline` はインタプリタでは動かないので、`load.lisp` が必ずコンパイルしてから読み込む。
- 計算ロジック (`post` / `regen` / `admin` / `dai` / `config` など) はほとんど変更していない。

## 置き換えの対応表

| SBCL | ECL 版 |
|---|---|
| `sb-posix:stat` / `fstat` / `stat-*` | `os-stat` / `os-fstat` / `st-mode` `st-size` `st-mtime` `st-ctime` `st-nlink` (C の `stat` を包んだ関数) |
| `sb-posix:open` `close` `rename` `link` `chmod` `mkdir` `getpid` | `os-open` `os-close` `os-rename` `os-link` `os-chmod` `os-mkdir` `os-getpid` |
| `sb-posix:write` + `sb-sys:vector-sap` | `os-write` (octet vector を直接 `write(2)` へ) |
| `sb-posix:getenv` / `getcwd` | `ext:getenv` / `ext:getcwd` |
| `sb-alien` の `flock` | `c-flock` (`c-inline`) |
| `sb-ext:run-program` ほか | `proc-start` / `proc-wait` / `proc-kill` / `run-status` / `run-first-line` (`ext:run-program` を包んだもの) |
| `sb-ext:string-to-octets` / `octets-to-string` | `utf8` (自前) / `utf8-decode` / `utf8-decode-strict` |
| `sb-ext:get-time-of-day` | `os-epoch-now` (`get-universal-time` から) |
| `sb-ext:exit :code` | `os-exit` (標準出力を流してから `ext:quit`) |
| `sb-sys:make-fd-stream` | `ext:make-stream-from-fd` |
| `sb-thread:make-thread` | `mp:process-run-function` |
| `sb-sys:interactive-interrupt` | C のシグナルハンドラでフラグを立て、`serve` が監視 (`os-stop-requested-p`) |
| `sb-bsd-sockets` | そのまま (ECL の `(require :sockets)` が同名パッケージを提供) |
| `touch -d @EPOCH` (外部コマンド) | `os-utimes` (`utimes(2)`) |
| `directory` によるフォルダ一覧 | `os-listdir` (`readdir(3)`) |
| `with-open-file :supersede` による書き込み | `write-file-octets` (`open(O_TRUNC)` + `write`。inode を保つので flock が有効) |

## 速度のための C 化

純 Lisp の SHA-256 は ECL では 1 ブロック約 30µs で、PBKDF2 (10万回) が約 36 秒かかった。
圧縮関数と PBKDF2 の繰り返しループを C (`crypto.lisp` の `ffi:clines`) にして約 0.06 秒になった。
結果は Python の `hashlib.pbkdf2_hmac` と照合済み。

## 起動方法の変更

- `ecl --norc --shell amezo.lisp -- 引数…` (`--` より後ろがアプリの引数)
- `run.sh` / `archive.sh` はこの形で ecl を呼ぶ
- `amezo.lisp` は ECL が `require` やコンパイラ読み込み時に出す `;;; Loading ...` を止める (`--make-hash` の出力を汚すため)

## 動作確認

- `tests/unit-test.lisp` 37/37、`tests/port_test.py` 27/27、`tests/archive_test.py` 11/11 (ECL 21.2.1)
- `--cgi` の GET/POST、`archive.sh --selftest`、`--setup-tunnel` (cloudflared のダウンロードと実行)、Ctrl+C での終了
- 未確認: `--tunnel` での実際の公開 (外部ネットワークに出られないため)、`tests/interop_test.py` (Python 版が必要)
