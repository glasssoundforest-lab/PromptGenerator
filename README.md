# Prompt Generator (0.9.0 β)

日本語で選んだ項目から、画像生成用の英語プロンプトを作る Windows 向けデスクトップアプリです (Rust / egui)。

- 出力モデル: Midjourney / Stable Diffusion / DALL·E / Illustrious / NoobAI / Anima / Pony
- 簡易モードと詳細設定、辞書から種類ごとにまとめて選択、お気に入り、自動保存
- コピーモード: 分類つき(日本語・英語)/ 英単語のみ
- ネガティブプロンプト: 辞書(`Dict/dictionary.json`)から選択、モデル標準の追加、モデルに応じた振り分け
- 辞書は `Dict` フォルダの JSON / `.rs` を編集して差し替え可能 (`Dict/template.rs` を参照)

## 使い方
[Releases](../../releases) の zip を展開し、`PromptGenerator.exe` を起動します。設定は exe の隣の `settings.ini` / `state.json` に保存されます。

## ビルド
```
cargo build --release
```

## 注意
- 0.9β のため、不具合や仕様変更があります。
- 辞書には成人向け・ネガティブ用途の語も含まれます。
- AI 機能を使う場合の API キーは、利用者の PC 上でのみ保存されます (リポジトリには含まれません)。
