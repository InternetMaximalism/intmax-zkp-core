# コーディング規約

- 基本的に plonky2 の規約に従う
- test は module 内に記述する
- Target の構造体は`add_virtual_to`と`set_witness`を impl する
- `set_witness`では非 Target 版の構造体の`calc`を呼び出し、validation をかける
- prove する際は circuit データのみを出力する`data`と、有限体の計算結果のみを出力する`calc`を impl する
- prove する箇所には単体テストをつける

# 疑問点

## transaction

`circuit`と`gadgets`、その他名前がついているディレクトリ(`tree`や`utils`の使い分けは？)
