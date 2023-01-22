# コーディング規約

- 基本的に plonky2 の規約に従う
- test は module 内に記述する
- Target の構造体は`new`と`set_witness`を impl する
- `set_witness`では非 Target 版の構造体の`calc`を呼び出し、validation をかける
- prove する際は circuit データのみを出力する`data`と、有限体の計算結果のみを出力する`calc`を impl する
- prove する箇所には単体テストをつける

# 疑問点

## transaction

- `circuit`と`gadgets`、その他名前がついているディレクトリ(`tree`や`utils`の使い分けは？)

- `get_merkle_root`を`sparse_merkle_tree`と統合したほうが良いのではないか。

- `PurgeInputProcessProof`の`calculate`で`H::hash_or_noop`などを使用していたのが気になった。ハッシュのロジックは merkle tree(または sparse merkle tree)の決められたロジックを使ったほうが良さそう。

- `PurgeInputProcessProof`は Merkle 木の指定されたリーフを消去する proof なので、`DeleteLeafProof`などとしたほうが良いのでは

- `PurgeInputProcessProof`の`Proof`は、他の命名の整合性を考えると`Witness`の方が適当ではないか？

<!-- - `new`(`add_virtual_to`)と、`calculate`は完全に対応させたほうが良いのではないか？つまり、入力と出力の関係を完全に対応させたほうが良いのではないか？ -->
