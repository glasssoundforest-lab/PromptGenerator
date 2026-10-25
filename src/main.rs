#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod dict;

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, RichText, Stroke,
};

const BG: Color32 = Color32::from_rgb(10, 16, 36);
const PANEL: Color32 = Color32::from_rgb(14, 22, 48);
const INPUT: Color32 = Color32::from_rgb(12, 19, 42);
const BORDER: Color32 = Color32::from_rgb(40, 56, 105);
const ACCENT: Color32 = Color32::from_rgb(70, 80, 210);
const TEXT: Color32 = Color32::from_rgb(225, 230, 245);
const CHIP: Color32 = Color32::from_rgb(28, 110, 120);
const LABEL_W: f32 = 120.0;
const RANDOM_BTN_W: f32 = 76.0;
const DICT_BTN_W: f32 = 44.0;
const SUB: Color32 = Color32::from_rgb(110, 135, 200);

/// 簡易乱数 (xorshift)。外部クレート不要。
struct Rng(u64);
impl Rng {
    fn new() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(88172645463325252);
        Rng(t | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// n個の選択肢と「空白」から1つ選ぶ。空白(未選択)は None
    fn opt(&mut self, n: usize) -> Option<usize> {
        let i = (self.next() % (n as u64 + 1)) as usize;
        (i < n).then_some(i)
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        if items.is_empty() {
            return "";
        }
        items[(self.next() % items.len() as u64) as usize]
    }
}

/// ボタン(辞書)から入力された語。画面には日本語、プロンプトには英語を使う
#[derive(Clone)]
struct Tok {
    ja: String,
    en: String,
}

/// 区切り文字: 半角/全角スペース・タブ・改行、カンマ(, ，)、読点(、)、セミコロン(; ；)
fn split_free(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || matches!(c, ',' | '，' | '、' | ';' | '；'))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

#[derive(Clone, Default)]
struct FieldState {
    tokens: Vec<Tok>,
    free: String,
}

/// 非同期で走らせているAPI処理の種類
#[derive(Clone, Copy, PartialEq)]
enum ApiJob {
    Generate,
    Adjust,
}

/// 英語化に使うLLM API。切り替えても各社の設定は保持する
#[derive(Clone, Copy, PartialEq)]
enum Provider {
    Claude,
    Gpt,
    Gemini,
}

impl Provider {
    const ALL: [Provider; 3] = [Provider::Claude, Provider::Gpt, Provider::Gemini];

    fn name(self) -> &'static str {
        match self {
            Provider::Claude => "Claude (Anthropic)",
            Provider::Gpt => "GPT (OpenAI / OpenAI互換)",
            Provider::Gemini => "Gemini (Google)",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone)]
struct ProviderCfg {
    base_url: String,
    model: String,
    key: String,
    /// ロック中: キーは暗号化してINIに保存済みで、画面ではグレーアウト(編集・コピー不可)
    locked: bool,
}

/// APIキーは、ロックしたときだけ暗号化してINIに保存する。未ロックならメモリ上のみ
/// (各社の環境変数 ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY を初期値に使う)
#[derive(Clone)]
struct ApiSettings {
    enabled: bool,
    provider: Provider,
    cfg: [ProviderCfg; 3],
}

impl ApiSettings {
    fn cur(&self) -> &ProviderCfg {
        &self.cfg[self.provider.index()]
    }

    fn cur_mut(&mut self) -> &mut ProviderCfg {
        &mut self.cfg[self.provider.index()]
    }
}

impl Default for ApiSettings {
    fn default() -> Self {
        let cfg = |url: &str, model: &str, envs: &[&str]| ProviderCfg {
            base_url: url.into(),
            model: model.into(),
            key: envs
                .iter()
                .find_map(|e| std::env::var(e).ok())
                .unwrap_or_default(),
            locked: false,
        };
        ApiSettings {
            enabled: false,
            provider: Provider::Claude,
            cfg: [
                cfg(
                    "https://api.anthropic.com/v1",
                    "claude-haiku-5-5",
                    &["ANTHROPIC_API_KEY"],
                ),
                cfg(
                    "https://api.openai.com/v1",
                    "gpt-4o-mini",
                    &["OPENAI_API_KEY"],
                ),
                cfg(
                    "https://generativelanguage.googleapis.com/v1beta",
                    "gemini-2.5-flash",
                    &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
                ),
            ],
        }
    }
}

/// Windows DPAPI (ユーザーアカウントに紐づく暗号化)。他のユーザー・他のPCでは復号できない
#[cfg(windows)]
mod dpapi {
    use std::ffi::c_void;

    #[repr(C)]
    struct Blob {
        cb: u32,
        pb: *mut u8,
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            din: *const Blob,
            descr: *const u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            dout: *mut Blob,
        ) -> i32;
        fn CryptUnprotectData(
            din: *const Blob,
            descr: *mut *mut u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            dout: *mut Blob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h: *mut c_void) -> *mut c_void;
    }

    const UI_FORBIDDEN: u32 = 0x1;
    /// このアプリ専用の追加データ (他のアプリが同じユーザーで復号しにくくする)
    const ENTROPY: &[u8] = b"PromptGenerator/api-key/v1";

    fn run(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
        let din = Blob {
            cb: data.len() as u32,
            pb: data.as_ptr() as *mut u8,
        };
        let ent = Blob {
            cb: ENTROPY.len() as u32,
            pb: ENTROPY.as_ptr() as *mut u8,
        };
        let mut out = Blob {
            cb: 0,
            pb: std::ptr::null_mut(),
        };
        // SAFETY: すべてのポインタは呼び出し中有効。出力バッファはLocalFreeで解放する
        let ok = unsafe {
            if protect {
                CryptProtectData(
                    &din,
                    std::ptr::null(),
                    &ent,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    UI_FORBIDDEN,
                    &mut out,
                )
            } else {
                CryptUnprotectData(
                    &din,
                    std::ptr::null_mut(),
                    &ent,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    UI_FORBIDDEN,
                    &mut out,
                )
            }
        };
        if ok == 0 || out.pb.is_null() {
            return Err(if protect {
                "暗号化に失敗しました".into()
            } else {
                "復号に失敗しました".into()
            });
        }
        let v = unsafe { std::slice::from_raw_parts(out.pb, out.cb as usize).to_vec() };
        // 復号したキーが残らないよう、ゼロで上書きしてから解放する
        unsafe {
            std::ptr::write_bytes(out.pb, 0, out.cb as usize);
            LocalFree(out.pb as *mut c_void);
        }
        Ok(v)
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        run(data, false)
    }
}

#[cfg(not(windows))]
mod dpapi {
    pub fn protect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("この環境では暗号化に対応していません".into())
    }

    pub fn unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("この環境では復号に対応していません".into())
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 旧バージョンの保存先 (%APPDATA%\\PromptGenerator)。実行ファイルのフォルダに書き込めないときの保存先も兼ねる
fn appdata_dir() -> std::path::PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("PromptGenerator")
}

/// 設定(settings.ini)と作業内容(state.json)の保存フォルダ: 実行ファイルと同じフォルダ。
/// そのフォルダに書き込めない場合(Program Files など)だけ、%APPDATA%\\PromptGenerator に保存する
fn data_dir() -> std::path::PathBuf {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            let probe = dir.join(".pg_write_test");
            if std::fs::write(&probe, b"").is_ok() {
                let _ = std::fs::remove_file(&probe);
                return dir;
            }
        }
        appdata_dir()
    })
    .clone()
}

fn ini_path() -> std::path::PathBuf {
    data_dir().join("settings.ini")
}

/// 旧バージョンが %APPDATA% に作った settings.ini (暗号化キー入り) と state.json を、新しい保存先へ移す
fn migrate_legacy_files() {
    for name in ["settings.ini", "state.json"] {
        let (new, old) = (data_dir().join(name), appdata_dir().join(name));
        if new != old && !new.exists() && old.exists() && std::fs::copy(&old, &new).is_ok() {
            let _ = std::fs::remove_file(&old);
        }
    }
}

/// 最小限のINI読み込み。`[section]` の下の `key=value` を `section.key` として集める (`;` `#` はコメント)
fn ini_parse(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.trim().to_string();
        } else if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let key = if section.is_empty() {
                k.to_string()
            } else {
                format!("{section}.{k}")
            };
            map.insert(key, v.trim().to_string());
        }
    }
    map
}

/// `section.key` のマップをINI文章にする
fn ini_render(map: &std::collections::BTreeMap<String, String>) -> String {
    let mut s = String::from(
        "; Prompt Generator 設定 (APIキーはWindowsのユーザーアカウントで暗号化されています)\n",
    );
    let mut current = String::new();
    for (k, v) in map {
        let (sec, key) = k.split_once('.').unwrap_or(("general", k.as_str()));
        if sec != current {
            s += &format!("\n[{sec}]\n");
            current = sec.to_string();
        }
        s += &format!("{key}={v}\n");
    }
    s
}

/// 設定ファイルの読み込み: 大きすぎるファイルは読まず、UTF-8のBOM (メモ帳で保存すると付く) は取り除く
/// 辞書の置き場: 実行ファイルと同じフォルダの Dict
const DEFAULT_DICT: &str = "dictionary.json";

fn dict_dir() -> std::path::PathBuf {
    data_dir().join("Dict")
}

/// Dict フォルダ直下の安全な .json / .rs ファイル名か
fn dict_file_ok(name: &str) -> bool {
    (name.to_lowercase().ends_with(".json") || name.to_lowercase().ends_with(".rs")) && !name.contains(['\\', '/', ':']) && name != "." && name != ".."
}

/// Dict フォルダの辞書ファイル名 (.json / .rs) (名前順)
fn dict_files() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dict_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| dict_file_ok(n))
        .collect();
    v.sort();
    v
}

fn read_text_limited(path: &std::path::Path, max_bytes: u64) -> Option<String> {
    if std::fs::metadata(path).ok()?.len() > max_bytes {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    Some(
        text.strip_prefix('\u{feff}')
            .map(str::to_string)
            .unwrap_or(text),
    )
}

fn ini_read(path: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    read_text_limited(path, 1 << 20)
        .map(|t| ini_parse(&t))
        .unwrap_or_default()
}

fn ini_write(
    path: &std::path::Path,
    map: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if map.is_empty() {
        // 保存するキーが無ければファイルごと削除する
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("INIの削除に失敗: {e}")),
        };
    }
    // 書き込み途中で落ちても、暗号化キーを含むINIが壊れないよう、一時ファイル経由で置き換える
    let tmp = path.with_extension("ini.tmp");
    std::fs::write(&tmp, ini_render(map))
        .and_then(|_| std::fs::rename(&tmp, path))
        .map_err(|e| format!("INIの保存に失敗: {e}"))
}

const KEY_NAMES: [&str; 3] = ["api.claude_key", "api.gpt_key", "api.gemini_key"];
const PROVIDER_IDS: [&str; 3] = ["claude", "gpt", "gemini"];

/// 文字列の中身をゼロで上書きしてから空にする (clear() だけでは、キーがメモリに残る)
fn wipe(s: &mut String) {
    // SAFETY: 0バイトだけで埋めてもUTF-8として有効
    unsafe { s.as_bytes_mut().fill(0) };
    s.clear();
}

impl ApiSettings {
    /// 選択中APIのキーをロックする: 暗号化してINIに保存し、画面ではグレーアウトする。
    /// 解除する: INIに保存したキーを削除し、入力欄のキーも消す
    fn set_lock(&mut self, lock: bool, path: &std::path::Path) -> Result<(), String> {
        let idx = self.provider.index();
        let mut map = ini_read(path);
        if lock {
            let key = self.cfg[idx].key.trim().to_string();
            if key.is_empty() {
                return Err("キーを入力してからロックしてください".into());
            }
            map.insert(
                KEY_NAMES[idx].into(),
                hex_encode(&dpapi::protect(key.as_bytes())?),
            );
            ini_write(path, &map)?;
            self.cfg[idx].key = key;
            self.cfg[idx].locked = true;
        } else {
            map.remove(KEY_NAMES[idx]);
            ini_write(path, &map)?;
            wipe(&mut self.cfg[idx].key);
            self.cfg[idx].locked = false;
        }
        Ok(())
    }

    /// INIに保存された(暗号化済みの)キーを読み込み、ロック状態にする
    fn load_locked_keys(&mut self, path: &std::path::Path) {
        let map = ini_read(path);
        for (i, c) in self.cfg.iter_mut().enumerate() {
            let plain = map
                .get(KEY_NAMES[i])
                .and_then(|h| hex_decode(h))
                .and_then(|b| dpapi::unprotect(&b).ok())
                .and_then(|p| String::from_utf8(p).ok());
            if let Some(key) = plain.filter(|k| !k.is_empty()) {
                c.key = key;
                c.locked = true;
            }
        }
    }
}

/// 生成: 選択内容 -> 対象モデル向けの最終プロンプト (ポジティブ/ネガティブ)
fn generate_system_prompt(f: &Format) -> String {
    format!(
        "You are an expert prompt writer for the image-generation model \"{name}\". \
Convert the user's selections into the final prompt for that model. The input is a JSON object: \
\"selections\" holds the character/scene elements (Japanese and/or English, comma-separated) and \"negative\" holds things to avoid. \
Write everything in English: translate every Japanese term into a concise English descriptor, keep English terms, and do not invent new concepts. \
Format rules for {name}: {hint} \
Put the main prompt in \"positive\". Put only the things to avoid in \"negative\" (translated); if the input negative is empty, return an empty string. \
Output ONLY a JSON object with exactly two string fields, {{\"positive\": \"...\", \"negative\": \"...\"}}. \
No explanations, labels, markdown, or Japanese text.",
        name = f.name,
        hint = f.hint,
    )
}

/// 修正: 現在のポジティブ/ネガティブ + 修正内容 -> 修正後のポジティブ/ネガティブ
fn adjust_system_prompt(f: &Format) -> String {
    format!(
        "You edit an existing prompt for the image-generation model \"{name}\". The input is a JSON object with \"positive\" and \"negative\" (the current prompts) \
and \"instruction\" (the requested change, in Japanese or English). Apply only the requested change, and keep everything else as is, including any quality tags. \
If the instruction is about things to avoid, edit \"negative\"; otherwise edit \"positive\". Keep the format rules for {name}: {hint} \
Write everything in English. Output ONLY a JSON object with exactly two string fields, {{\"positive\": \"...\", \"negative\": \"...\"}}. \
No explanations, labels, markdown, or Japanese text.",
        name = f.name,
        hint = f.hint,
    )
}

/// LLMの応答から「プロンプト本文だけ」を取り出す。
/// コードブロックがあればその中身だけを使い、前置き・ラベル・引用符・改行を除去する
fn clean_prompt(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(i) = s.find("```") {
        let inner = &s[i + 3..];
        let inner = inner.split("```").next().unwrap_or(inner);
        // 先頭行が言語名だけ (例: text) なら捨てる
        let inner = match inner.split_once('\n') {
            Some((first, rest))
                if !first.trim().is_empty()
                    && !first.trim().contains(' ')
                    && !first.contains(',') =>
            {
                rest
            }
            _ => inner,
        };
        s = inner.trim().to_string();
    }
    let lower = s.to_lowercase();
    for label in ["english prompt:", "negative prompt:", "prompt:"] {
        if lower.starts_with(label) {
            s = s[label.len()..].trim().to_string();
            break;
        }
    }
    let s = s
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '「' | '」'))
        .trim();
    let lines: Vec<&str> = s
        .split(['\n', '\r'])
        .map(|l| l.trim().trim_end_matches(',').trim())
        .filter(|l| !l.is_empty())
        .collect();
    lines
        .join(", ")
        .trim_end_matches(['.', '。'])
        .trim()
        .to_string()
}

/// 応答から {"positive","negative"} を取り出す (JSON優先、無ければ "Negative prompt:" ラベルで分割)。
/// 英語以外の文字が残っていたらエラー
fn parse_pos_neg(raw: &str) -> Result<(String, String), String> {
    let t = raw.trim();
    if let (Some(i), Some(j)) = (t.find('{'), t.rfind('}')) {
        if i < j {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t[i..=j]) {
                let get = |keys: &[&str]| {
                    keys.iter()
                        .find_map(|k| v[*k].as_str())
                        .map(clean_prompt)
                        .unwrap_or_default()
                };
                return check_english(
                    get(&["positive", "positive_prompt"]),
                    get(&["negative", "negative_prompt"]),
                );
            }
        }
    }
    let label = "negative prompt:";
    let (pos, neg) = match t.to_ascii_lowercase().find(label) {
        Some(i) => (&t[..i], &t[i + label.len()..]),
        None => (t, ""),
    };
    check_english(clean_prompt(pos), clean_prompt(neg))
}

fn check_english(pos: String, neg: String) -> Result<(String, String), String> {
    if pos.is_empty() && neg.is_empty() {
        return Err("応答が空でした".into());
    }
    if !pos.is_ascii() || !neg.is_ascii() {
        return Err("応答に英語以外の文字が含まれていました".into());
    }
    Ok((pos, neg))
}

/// 生成: 選択内容を、対象モデル向けのポジティブ/ネガティブにしてAIから受け取る
fn llm_generate(
    api: &ApiSettings,
    f: &Format,
    selections: &str,
    negative: &str,
) -> Result<(String, String), String> {
    let user = serde_json::json!({"selections": selections, "negative": negative}).to_string();
    parse_pos_neg(&llm_raw(api, &generate_system_prompt(f), &user)?)
}

/// 修正: 現在のポジティブ/ネガティブと修正内容をAIに渡し、修正後のポジティブ/ネガティブを受け取る
fn llm_adjust(
    api: &ApiSettings,
    f: &Format,
    positive: &str,
    negative: &str,
    instruction: &str,
) -> Result<(String, String), String> {
    let user =
        serde_json::json!({"positive": positive, "negative": negative, "instruction": instruction})
            .to_string();
    parse_pos_neg(&llm_raw(api, &adjust_system_prompt(f), &user)?)
}

/// APIキーを送る先の検査: 暗号化されない http:// は、自分のPC内(localhost / 127.0.0.1 / ::1)のLLMだけ許可する。
/// それ以外のhttpでは、キーが通信経路に平文で流れるため拒否する
fn check_base_url(url: &str) -> Result<(), String> {
    let u = url.trim();
    if u.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = u.strip_prefix("http://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h); // ユーザー情報部は無視して本当のホストを見る
        let host = if let Some(v6) = host.strip_prefix('[') {
            v6.split(']').next().unwrap_or("")
        } else {
            host.split(':').next().unwrap_or("")
        };
        if matches!(host, "localhost" | "127.0.0.1" | "::1") {
            return Ok(());
        }
        return Err("http:// の接続先にはAPIキーを送れません (自分のPC内のLLM以外は https:// にしてください)".into());
    }
    Err("ベースURLは https:// で始めてください".into())
}

/// 選択中のLLM APIに、システムプロンプトとユーザー入力を送り、応答本文をそのまま返す
fn llm_raw(api: &ApiSettings, sys: &str, text: &str) -> Result<String, String> {
    check_base_url(&api.cur().base_url)?;
    let c = api.cur();
    let key = c.key.trim();
    if key.is_empty() && api.provider != Provider::Gpt {
        return Err("APIキーが未設定です。「API設定」で入力してください".into());
    }
    let base = c.base_url.trim_end_matches('/');
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let (v, pick): (serde_json::Value, &[&str]) = match api.provider {
        Provider::Claude => {
            let body = serde_json::json!({
                "model": c.model,
                "max_tokens": 1024,
                "temperature": 0.2,
                "system": sys,
                "messages": [{"role": "user", "content": text}],
            });
            let resp = agent
                .post(&format!("{base}/messages"))
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .send_json(&body);
            (read_json(resp)?, &["content", "0", "text"])
        }
        Provider::Gpt => {
            let body = serde_json::json!({
                "model": c.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": sys},
                    {"role": "user", "content": text},
                ],
            });
            let mut req = agent.post(&format!("{base}/chat/completions"));
            if !key.is_empty() {
                req = req.header("Authorization", format!("Bearer {key}"));
            }
            (
                read_json(req.send_json(&body))?,
                &["choices", "0", "message", "content"],
            )
        }
        Provider::Gemini => {
            let body = serde_json::json!({
                "systemInstruction": {"parts": [{"text": sys}]},
                "contents": [{"role": "user", "parts": [{"text": text}]}],
                "generationConfig": {"temperature": 0.2},
            });
            let resp = agent
                .post(&format!("{base}/models/{}:generateContent", c.model))
                .header("x-goog-api-key", key)
                .send_json(&body);
            (
                read_json(resp)?,
                &["candidates", "0", "content", "parts", "0", "text"],
            )
        }
    };
    let content = pick.iter().try_fold(&v, |cur, k| match k.parse::<usize>() {
        Ok(i) => cur.get(i),
        Err(_) => cur.get(*k),
    });
    let content = content
        .and_then(|x| x.as_str())
        .ok_or("応答に本文がありません")?;
    Ok(content.to_string())
}

/// 選択中のAPIサーバーに問い合わせて、現在使えるモデルID一覧を取得する
fn fetch_models(api: &ApiSettings) -> Result<Vec<String>, String> {
    check_base_url(&api.cur().base_url)?;
    let c = api.cur();
    let key = c.key.trim();
    if key.is_empty() && api.provider != Provider::Gpt {
        return Err("APIキーが未設定です。「API設定」で入力してください".into());
    }
    let base = c.base_url.trim_end_matches('/');
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let mut ids: Vec<String> = match api.provider {
        Provider::Claude => {
            let resp = agent
                .get(&format!("{base}/models?limit=1000"))
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .call();
            let v = read_json(resp)?;
            v["data"]
                .as_array()
                .ok_or("応答にモデル一覧がありません")?
                .iter()
                .filter_map(|m| m["id"].as_str().map(String::from))
                .collect()
        }
        Provider::Gpt => {
            let mut req = agent.get(&format!("{base}/models"));
            if !key.is_empty() {
                req = req.header("Authorization", format!("Bearer {key}"));
            }
            let v = read_json(req.call())?;
            let skip = [
                "embedding",
                "whisper",
                "tts",
                "dall-e",
                "moderation",
                "davinci",
                "babbage",
                "transcribe",
                "realtime",
                "audio",
                "image",
            ];
            v["data"]
                .as_array()
                .ok_or("応答にモデル一覧がありません")?
                .iter()
                .filter_map(|m| m["id"].as_str())
                .filter(|id| !skip.iter().any(|s| id.contains(s)))
                .map(String::from)
                .collect()
        }
        Provider::Gemini => {
            let resp = agent
                .get(&format!("{base}/models?pageSize=1000"))
                .header("x-goog-api-key", key)
                .call();
            let v = read_json(resp)?;
            v["models"]
                .as_array()
                .ok_or("応答にモデル一覧がありません")?
                .iter()
                .filter(|m| {
                    m["supportedGenerationMethods"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|x| x == "generateContent"))
                })
                .filter_map(|m| m["name"].as_str())
                .map(|n| n.trim_start_matches("models/").to_string())
                .collect()
        }
    };
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err("使えるモデルが見つかりませんでした".into());
    }
    Ok(ids)
}

fn read_json(
    resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<serde_json::Value, String> {
    let mut resp = resp.map_err(|e| format!("通信エラー: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        // サーバーのエラーメッセージ本文を取り出して、原因が分かるようにする
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v["error"]["message"]
                    .as_str()
                    .or(v["error"].as_str())
                    .or(v["message"].as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| text.chars().take(200).collect());
        let msg: String = msg.trim().chars().take(300).collect();
        return Err(format!("HTTP {}: {}", status.as_u16(), msg));
    }
    resp.body_mut()
        .read_json()
        .map_err(|e| format!("応答の解析に失敗: {e}"))
}

struct Field {
    label: &'static str,
    hint: &'static str,
    state: FieldState,
    candidates: &'static [&'static str],
    /// 辞書カテゴリID (dict.rs)。指定時はランダム・辞書ピッカーが辞書を使う
    dicts: &'static [&'static str],
    /// 簡易モードでも表示する項目
    simple: bool,
}

impl Field {
    fn dict(mut self, dicts: &'static [&'static str]) -> Self {
        self.dicts = dicts;
        self
    }

    /// 辞書の語から1つ選ぶ。空白(何も選ばない)も選択肢に含み、その場合は None
    fn random(&self, rng: &mut Rng) -> Option<Tok> {
        let total: usize = self.dicts.iter().filter_map(|id| dict::category(id)).map(|c| c.entries.len()).sum();
        if total == 0 {
            let s = self.candidates.get(rng.opt(self.candidates.len())?)?.to_string();
            return Some(Tok { ja: s.clone(), en: s });
        }
        let mut n = rng.opt(total)?;
        for c in self.dicts.iter().filter_map(|id| dict::category(id)) {
            if n < c.entries.len() {
                let (en, ja) = c.entries[n];
                return Some(Tok { ja: ja.into(), en: en.into() });
            }
            n -= c.entries.len();
        }
        None
    }

    fn randomize(&mut self, rng: &mut Rng) {
        self.state = FieldState {
            tokens: self.random(rng).into_iter().collect(),
            free: String::new(),
        };
    }

    fn has(&self, en: &str) -> bool {
        self.state.tokens.iter().any(|t| t.en == en)
    }

    /// 辞書の語を追加。選択済みなら外す
    fn toggle(&mut self, en: &str, ja: &str) {
        if self.has(en) {
            self.state.tokens.retain(|t| t.en != en);
        } else {
            self.state.tokens.push(Tok {
                ja: ja.into(),
                en: en.into(),
            });
        }
    }

    /// プロンプトに使う語。ボタン入力は英語、自由入力は区切って使う。
    /// `lookup` が真なら、辞書に一致する自由入力を英語に置換する (API英語化を使うときは不要)
    fn prompt_terms(&self, lookup: bool) -> Vec<String> {
        let mut out: Vec<String> = self.state.tokens.iter().map(|t| t.en.clone()).collect();
        for w in split_free(&self.state.free) {
            let hit = if lookup {
                dict::lookup_compound(self.dicts, &w)
            } else {
                None
            };
            out.push(hit.unwrap_or(w));
        }
        out
    }
}

struct Section {
    title: &'static str,
    sub: &'static str,
    /// 中分類: (名前, 含む項目数)。項目数の合計は fields の数と同じ
    groups: &'static [(&'static str, usize)],
    fields: Vec<Field>,
}

fn f(label: &'static str, hint: &'static str, candidates: &'static [&'static str]) -> Field {
    Field {
        label,
        hint,
        state: FieldState::default(),
        candidates,
        dicts: &[],
        simple: false,
    }
}

/// 簡易モードで表示する項目 (項目名)
const SIMPLE_FIELDS: &[&str] = &[
    "目・瞳", "髪型・長さ", "髪の色・髪質", "身長・体型・首", "制服・ドレス・水着", "トップス・ボトムス",
    "姿勢・動作", "視線・顔の向き", "表情・感情", "シチュエーション", "ライティング", "画風・描画テイスト",
    "雰囲気・色彩", "アングル・構図",
];

/// 大分類・項目名の英語名 (英語でコピーするときに使う)
fn en_label(ja: &str) -> &str {
    match ja {
        "顔・頭部" => "Face & Head",
        "身体" => "Body",
        "衣装・服装" => "Clothing",
        "ポーズ・動作" => "Pose & Action",
        "感情・表現" => "Emotion & Expression",
        "シーン・背景" => "Scene & Background",
        "画風・品質・技術" => "Style, Quality & Technique",
        "輪郭・鼻" => "Face outline & nose",
        "口・唇" => "Mouth & lips",
        "目・瞳" => "Eyes",
        "まつ毛・眉" => "Eyelashes & eyebrows",
        "肌" => "Skin",
        "髪型・長さ" => "Hairstyle & length",
        "前髪・結い髪・毛先" => "Bangs, tied hair & ends",
        "髪の色・髪質" => "Hair color & texture",
        "メガネ・帽子・耳飾り" => "Eyewear, headwear & ear accessories",
        "瞳の状態(成人向け)" => "Eye state (adult)",
        "身長・体型・首" => "Height, build & neck",
        "胸・ウエスト・ヒップ" => "Chest, waist & hips",
        "手・腕・脚・足" => "Hands, arms, legs & feet",
        "身体・部位(成人向け)" => "Body parts (adult)",
        "制服・ドレス・水着" => "Uniform, dress & swimwear",
        "トップス・ボトムス" => "Tops & bottoms",
        "靴下・靴" => "Legwear & shoes",
        "ファッション系統" => "Fashion style",
        "素材・質感" => "Material & texture",
        "アクセサリー・バッグ・小物" => "Accessories, bags & small items",
        "衣装の状態・拘束(成人向け)" => "Clothing state & restraints (adult)",
        "姿勢・動作" => "Posture & motion",
        "腕・手の仕草" => "Arm & hand gestures",
        "視線・顔の向き" => "Gaze & face direction",
        "ポーズ・行為(成人向け)" => "Pose & acts (adult)",
        "表情・感情" => "Expression & emotion",
        "表情・反応(成人向け)" => "Expression & reaction (adult)",
        "シチュエーション" => "Situation",
        "ライティング" => "Lighting",
        "画風・描画テイスト" => "Art style",
        "雰囲気・色彩" => "Mood & color",
        "品質" => "Quality",
        "アングル・構図" => "Camera angle & composition",
        "レンズ・臨場感" => "Lens & immersion",
        other => other,
    }
}

fn build_sections() -> Vec<Section> {
    let mut v = build_all_sections();
    for fl in v.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        fl.simple = SIMPLE_FIELDS.contains(&fl.label);
    }
    v
}

/// 最初から入っている語 (項目名 -> (日本語, 英語))。入力欄の✕で削除できる
const DEFAULT_TOKENS: &[(&str, &[(&str, &str)])] = &[
    ("雰囲気・色彩", &[("色彩豊かな", "colorful"), ("フルカラー", "full color")]),
    ("品質", &[("完璧", "perfect"), ("マスターピース", "masterpiece")]),
];

fn default_state(label: &str) -> FieldState {
    let tokens = DEFAULT_TOKENS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, ws)| ws.iter().map(|(ja, en)| Tok { ja: ja.to_string(), en: en.to_string() }).collect())
        .unwrap_or_default();
    FieldState { tokens, free: String::new() }
}

fn build_all_sections() -> Vec<Section> {
    vec![
        Section {
            title: "顔・頭部",
            sub: "顔全体、目・口・肌・髪などの頭部パーツを指定できます。",
            groups: &[("顔のパーツ", 2), ("目・眉", 2), ("肌", 1), ("髪", 3), ("装飾", 1), ("成人向け", 1)],
            fields: vec![
                f("輪郭・鼻", "例：卵型の顔、まっすぐな鼻、丸顔、高い鼻筋 など", &["oval face"]).dict(&["face_nose", "face_shape", "face_balance", "face_age", "nose"]),
                f("口・唇", "例：ふっくらとした唇、口を閉じている、見える歯、不敵な笑み など", &["full lips"]).dict(&["mouth_all", "mouth", "mouth_opening", "mouth_internal", "mouth_expression_detail", "mouth_moisture"]),
                f("目・瞳", "例：大きな目、灰色の瞳、輝く瞳、小さな目 など", &["large eyes"]).dict(&["eye_all", "eye_shape", "eye_gaze_physical", "eye_color", "eye_state", "eye_pupil", "eye_light"]),
                f("まつ毛・眉", "例：長いまつげ、太い眉毛、濃いまつげ、細い眉毛 など", &["long eyelashes"]).dict(&["brow_lash", "eyelash", "eyebrow"]),
                f("肌", "例：色白肌、なめらかな肌、青白い肌、マットな肌 など", &["fair skin"]).dict(&["skin_all", "skin_tone", "skin_texture", "skin_detail", "skin_grain_realism", "skin_moisture_sheen", "skin_lighting_optics"]),
                f("髪型・長さ", "例：ミディアムヘア、ベリーショート、ボブカット、ショートヘア など", &["medium-length hair"]).dict(&["hair_cut", "hair_style_f", "hair_style_m", "hair_special", "hair_length"]),
                f("前髪・結い髪・毛先", "例：アーチバング、1本編み、カーリーヘア、アシメ前髪 など", &["arched bangs"]).dict(&["hair_arrange", "hair_bangs", "hair_sidelocks", "hair_braid", "hair_bun", "hair_tie", "hair_ends", "hair_top"]),
                f("髪の色・髪質", "例：黒髪、太い髪、漆黒の髪、細い髪 など", &["black hair"]).dict(&["hair_color_quality", "hair_color", "hair_tone", "hair_design", "hair_texture", "hair_texture_advanced", "hair_movement", "hair_detail"]),
                f("メガネ・帽子・耳飾り", "例：眼鏡、ヘアリボン、丸眼鏡、リボン など", &["glasses"]).dict(&["wear_all", "eyewear", "ear", "headwear"]),
                f("瞳の状態(成人向け)", "辞書ボタンから選べます (成人向けの語を含みます)", &["heart-shaped pupils"]).dict(&["eye_adult", "eye_nsfw_state"]),
            ],
        },
        Section {
            title: "身体",
            sub: "体全体の形状や部位のサイズ・状態を指定できます。",
            groups: &[("全体", 1), ("胴", 1), ("手足", 1), ("成人向け", 1)],
            fields: vec![
                f("身長・体型・首", "例：背の高い女性、長い首、脚の長い、短い首 など", &["tall girl"]).dict(&["body_head", "body_height", "body_figure", "neck", "body_neck_anatomy", "body_nape", "hair_neck_interaction"]),
                f("胸・ウエスト・ヒップ", "例：大きな胸、細いウエスト、幅広のヒップ、豊満なバスト など", &["large breasts"]).dict(&["torso", "body_bust", "body_waist", "body_midriff_state", "body_abs", "body_navel", "body_hips", "body_hips_volume", "body_hips_curve", "body_hips_structure"]),
                f("手・腕・脚・足", "例：細長い指、太い太もも、足の裏、詳細な爪 など", &["slender fingers"]).dict(&["limbs", "body_hand_anatomy", "body_limbs", "body_leg_thighs", "body_leg_lower", "body_foot_anatomy"]),
                f("身体・部位(成人向け)", "辞書ボタンから選べます (成人向けの語を含みます)", &["nipples"]).dict(&["body_adult", "body_adult_detail", "body_fetish_feet", "body_fetish_focus", "body_armpit_state", "body_armpit_detail"]),
            ],
        },
        Section {
            title: "衣装・服装",
            sub: "服の種類、素材、装飾を指定できます。",
            groups: &[("服装の種類", 4), ("素材", 1), ("小物", 1), ("成人向け", 1)],
            fields: vec![
                f("制服・ドレス・水着", "例：制服、ウェディングドレス、競泳水着、セーラー服 など", &["school uniform"]).dict(&["outfit", "cloth_costume", "cloth_school", "cloth_story", "cloth_dress", "cloth_wafuku", "cloth_swim"]),
                f("トップス・ボトムス", "例：パーカー、パンツ、革ジャン、ジーンズ など", &["hoodie"]).dict(&["tops_bottoms", "cloth_tops", "cloth_tops_detail", "cloth_bottoms", "cloth_skirt", "waist_clothes"]),
                f("靴下・靴", "例：レギンス、鮮やかな靴、タイツ、ハイヒール など", &["leggings"]).dict(&["legwear_shoes", "cloth_legwear", "shoes"]),
                f("ファッション系統", "例：カジュアル、シンプル、ミニマル、ナチュラル など", &["casual"]).dict(&["fashion_style"]),
                f("素材・質感", "例：シルク、詳細な布の折り目、メタリックな、コットン など", &["silk"]).dict(&["cloth_material", "cloth_material_general", "cloth_physical_state", "cloth_luster_finish"]),
                f("アクセサリー・バッグ・小物", "例：ネックレス、ランドセル、チョーカー、ベーシックデイパック など", &["necklace"]).dict(&["accessories", "accessory", "makeup", "bag", "keychain"]),
                f("衣装の状態・拘束(成人向け)", "辞書ボタンから選べます (成人向けの語を含みます)", &["naked"]).dict(&["cloth_adult", "cloth_nsfw_state", "cloth_fetish_material", "cloth_fetish_gear"]),
            ],
        },
        Section {
            title: "ポーズ・動作",
            sub: "体の動きや構え、視線を指定できます。",
            groups: &[("姿勢・動作", 2), ("視線", 1), ("成人向け", 1)],
            fields: vec![
                f("姿勢・動作", "例：立っている、走っている、手を繋ぐ、座っている など", &["standing"]).dict(&["pose_main", "pose_basic", "pose_stand", "pose_lean", "pose_action", "pose_skirt", "pose_together"]),
                f("腕・手の仕草", "例：片手を腰に置く、指を組んだ状態、逆立ち、しがみつくように掴む など", &["one hand on hip"]).dict(&["pose_hands", "pose_arms", "pose_hand_gesture", "pose_gesture", "pose_hand_interaction"]),
                f("視線・顔の向き", "例：わずかにこちらを見る、射抜くような視線、こちらを直視する、斜め上を見る など", &["looking slightly toward viewer"]).dict(&["gaze", "pose_gaze", "eye_gaze_intent", "eye_gaze_direction_advanced"]),
                f("ポーズ・行為(成人向け)", "辞書ボタンから選べます (成人向けの語を含みます)", &["spread legs"]).dict(&["pose_adult", "pose_nsfw", "pose_armpit_exposure"]),
            ],
        },
        Section {
            title: "感情・表現",
            sub: "内面的な感情や雰囲気を指定できます。",
            groups: &[("表情", 1), ("成人向け", 1)],
            fields: vec![
                f("表情・感情", "例：幸せそう、悲しい、無表情、喜んでいる など", &["happy"]).dict(&["expr_all", "expr_joy", "expr_negative", "expr_calm", "expr_face", "face_mood"]),
                f("表情・反応(成人向け)", "辞書ボタンから選べます (成人向けの語を含みます)", &["ahegao"]).dict(&["expr_adult", "expr_nsfw", "expr_sensual", "expr_ecstasy", "expr_nsfw_physical"]),
            ],
        },
        Section {
            title: "シーン・背景",
            sub: "場所、光、空気感を指定できます。",
            groups: &[("シチュエーション(場所)", 1), ("ライティング・光", 1)],
            fields: vec![
                f("シチュエーション", "例：街中、室内、海辺、夜 など", &["city street"]).dict(&["scene_situation"]),
                f("ライティング", "例：柔らかい光、ドラマチックな照明、暖かい照明、柔らかい自然光 など", &["soft lighting"]).dict(&["scene_light"]),
            ],
        },
        Section {
            title: "画風・品質・技術",
            sub: "画風、品質、カメラやレンズを指定できます。",
            groups: &[("画風・品質", 3), ("カメラ", 2)],
            fields: vec![
                f("画風・描画テイスト", "例：アニメ風、プロフェッショナル、3DCG、アーティスティック など", &["anime_style"]).dict(&["style_all", "style_genre", "style_technique"]),
                f("雰囲気・色彩", "例：映画的な雰囲気、色彩豊かな、魔法的な雰囲気、フルカラー など", &["cinematic atmosphere"]).dict(&["mood_color", "scene_mood", "color_palette"]),
                f("品質", "例：高品質、最高品質、超高画質、マスターピース など", &["high_quality"]).dict(&["style_quality"]),
                f("アングル・構図", "例：横顔、上半身、正面、カウボーイショット など", &["profile"]).dict(&["camera_all", "camera_angle", "camera_angle_advanced", "camera_framing", "camera_composition", "camera_shot_size"]),
                f("レンズ・臨場感", "例：シャープフォーカス、映画的なショット、ふんわり加工、躍動感のあるアングル など", &["sharp_focus"]).dict(&["camera_lens", "camera_movement_feel"]),
            ],
        },
    ]
}

/// コピー形式の名前 (App::copy_mode の番号)
const COPY_MODES: [&str; 3] = ["分類つき (日本語の見出し)", "分類つき (全て英語)", "英単語のみ (分類なし)"];

const GENDERS: [&str; 3] = ["男性", "女性", "その他"];
const AGES: [&str; 5] = ["10代", "20代", "30代", "40代", "50代以上"];
const COUNTS: [&str; 4] = ["1人", "2人", "3人", "複数"];
/// 性別・年齢の英語タグ (GENDERS / AGES と同じ並び)
const GENDER_TAGS: [&str; 3] = ["male", "female", "androgynous"];
const AGE_TAGS: [&str; 5] = [
    "teenager",
    "young adult",
    "adult",
    "middle-aged",
    "older adult",
];

/// 人数の英語タグ。2人以上は性別があれば 2girls / 2boys のようにする
fn count_tag(count: usize, gender: Option<usize>) -> String {
    let who = match gender {
        Some(0) => "boy",
        Some(1) => "girl",
        _ => "",
    };
    match (count, who) {
        (0, _) => "solo".into(),
        (1 | 2, "") => format!("{}people", count + 1),
        (1 | 2, w) => format!("{}{w}s", count + 1),
        (_, "") => "multiple people".into(),
        (_, w) => format!("multiple {w}s"),
    }
}
/// 出力形式。タグ系ローカルモデルは、公式カード/ガイドの推奨プレフィックス・ネガティブを既定にしている
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Midjourney,
    /// 自然文・キーワード系 (DALL·E)
    Sentence,
    /// 本文 + Negative prompt + Size 形式 (Stable Diffusion / ComfyUI / A1111 系)
    Webui,
}

struct Format {
    name: &'static str,
    kind: Kind,
    /// 品質タグ等のプレフィックス (LLMには渡さず、LLM後に付ける)
    prefix: &'static str,
    /// 既定のネガティブ (ユーザー入力のネガティブの前に付ける)
    neg: &'static str,
    /// LLMへの追加指示 (この形式の書き方)
    hint: &'static str,
}

const TAG_HINT: &str = "Write Danbooru-style tags: lowercase, comma-separated, spaces instead of underscores (e.g. 'long hair'). \
Start with a subject-count tag such as 1girl or 1boy when the gender is known. Use tags, not sentences. \
Do not output quality, score, rating, year, or artist tags; they are added separately.";

const FORMATS: [Format; 7] = [
    Format {
        name: "Midjourney",
        kind: Kind::Midjourney,
        prefix: "",
        neg: "",
        hint: "Write concise natural English phrases suitable for Midjourney. Do not output any --parameters.",
    },
    Format {
        name: "Stable Diffusion",
        kind: Kind::Webui,
        prefix: "",
        neg: "",
        hint: "Write comma-separated English keywords suitable for Stable Diffusion.",
    },
    Format {
        name: "DALL·E",
        kind: Kind::Sentence,
        prefix: "",
        neg: "",
        hint: "Write one or two descriptive English sentences suitable for DALL·E.",
    },
    Format {
        name: "Illustrious",
        kind: Kind::Webui,
        prefix: "masterpiece, best quality, amazing quality, highres",
        neg: "worst quality, low quality, bad quality, bad anatomy",
        hint: TAG_HINT,
    },
    Format {
        name: "NoobAI",
        kind: Kind::Webui,
        prefix: "masterpiece, best quality, newest, absurdres, highres, safe",
        neg: "nsfw, worst quality, old, early, low quality, lowres, signature, username, logo, bad hands, mutated hands",
        hint: TAG_HINT,
    },
    Format {
        name: "Anima",
        kind: Kind::Webui,
        prefix: "masterpiece, best quality, score_7, safe",
        neg: "worst quality, low quality, score_1, score_2, score_3, artist name, blurry, jpeg artifacts, chromatic aberration",
        hint: "Write lowercase Danbooru-style tags with spaces instead of underscores, optionally followed by one or two short natural-language sentences describing the scene. \
Start with a subject-count tag such as 1girl or 1boy when the gender is known. Do not output quality, score, rating, or artist tags; they are added separately.",
    },
    Format {
        name: "Pony",
        kind: Kind::Webui,
        prefix: "score_9, score_8_up, score_7_up, score_6_up, source_anime",
        neg: "score_6, score_5, score_4, text, watermark, signature",
        hint: TAG_HINT,
    },
];

/// アスペクト比 -> SDXL系の解像度 (約1MP)
const SIZES: [&str; 5] = ["1024x1024", "896x1152", "1152x896", "1344x768", "768x1344"];
const STYLES: [&str; 3] = ["raw", "default", "expressive"];
const ASPECTS: [&str; 5] = ["1:1", "3:4", "4:3", "16:9", "9:16"];
const NAV: [&str; 8] = [
    "画風・品質・技術",
    "キャラクター",
    "顔・頭部",
    "身体",
    "衣装・服装",
    "ポーズ・動作",
    "感情・表現",
    "シーン・背景",
];
/// 左ペインの表示順 (build_sections の番号。None = キャラクター設定カード)
const LAYOUT: [Option<usize>; 8] = [Some(6), None, Some(0), Some(1), Some(2), Some(3), Some(4), Some(5)];
/// ナビ項目 -> スクロール先 (セクション番号。usize::MAX = キャラクター設定カード)
const NAV_TARGET: [usize; 8] = [6, usize::MAX, 0, 1, 2, 3, 4, 5];

/// お気に入りのプロンプト (名前・ポジティブ・ネガティブ・出力モデル)
#[derive(Clone, PartialEq, Debug)]
struct Favorite {
    name: String,
    positive: String,
    negative: String,
    /// 出力モデル名 (FORMATS の name)
    model: String,
    /// Fav フォルダ内の MD ファイル名 (未保存なら空)
    file: String,
}

const MAX_FAVORITES: usize = 500;

#[derive(Clone)]
struct Saved {
    name: String,
    gender: Option<usize>,
    age: Option<usize>,
    count: Option<usize>,
    appearance: String,
    other: String,
    values: Vec<Vec<FieldState>>,
}

struct App {
    rng: Rng,
    gender: Option<usize>,
    age: Option<usize>,
    /// 人数 (COUNTS の番号)
    count: Option<usize>,
    appearance: String,
    /// その他の自由記述 (どの項目にも当てはまらないもの)
    other: String,
    sections: Vec<Section>,
    // output
    model: usize,
    quality_tags: bool,
    output: String,
    output_neg: String,
    /// 出力欄の下に出す補足 (推奨サイズ・シード等。プロンプト本文には含めない)
    output_note: String,
    /// Midjourney: --ar 等のパラメータ情報を付けない
    mj_no_params: bool,
    adjust: String,
    negative_input: String,
    negatives: Vec<String>,
    // params
    style: usize,
    aspect: usize,
    quality: f32,
    chaos: f32,
    stylize: f32,
    use_seed: bool,
    seed: String,
    // ui
    nav: usize,
    scroll_to: Option<usize>,
    /// 左ペインで折りたたんでいる大カテゴリ (LAYOUT の並びの番号。保存しない)
    folded: [bool; LAYOUT.len()],
    /// 簡易モード (主要な項目だけを表示)。false = 詳細設定
    simple_mode: bool,
    /// コピー形式: 0 = 日本語の見出し, 1 = 見出しも全て英語, 2 = 英単語のみ (分類なし)
    copy_mode: usize,
    /// スクロール量 [左ペイン, 右ペイン]。settings.ini に保存する
    scroll: [f32; 2],
    /// 起動直後に1度だけ、保存したスクロール量を戻す
    scroll_restore: [bool; 2],
    api: ApiSettings,
    show_api: bool,
    /// APIごとの取得済みモデル一覧
    models: [Vec<String>; 3],
    models_status: String,
    key_status: String,
    models_rx: Option<std::sync::mpsc::Receiver<(usize, Result<Vec<String>, String>)>>,
    api_status: String,
    api_fallback: (String, String),
    api_rx: Option<std::sync::mpsc::Receiver<Result<(String, String), String>>>,
    api_job: ApiJob,
    /// 自動保存: 最後に保存した内容と、最後に確認した時刻
    last_saved: String,
    last_save_check: f64,
    /// 直近のウィンドウ位置とサイズ [x, y, 幅, 高さ] (論理ピクセル)。次回起動時に復元する
    window: Option<[f32; 4]>,
    /// 最後に書いた settings.ini の内容
    last_ini: String,
    /// 調整のLLMが失敗したときに使う、ローカルで追記した結果
    adjust_fallback: String,
    dict_open: Option<(usize, usize)>,
    /// 直前のフレームで表示していた辞書 (開いた瞬間のクリックで閉じてしまわないための判定用)
    dict_shown: Option<(usize, usize)>,
    dict_filter: String,
    /// 辞書ピッカーで表示する辞書: 0 = 項目の辞書, 1 = 全ての辞書, 2以降 = dict::all() の番号+2
    dict_sel: usize,
    /// 使う外部辞書のファイル名 (Dict フォルダ内。空 = 組み込み)
    dict_file: String,
    show_dicts: bool,
    dict_msg: String,
    show_saved: bool,
    show_history: bool,
    saved: Vec<Saved>,
    history: Vec<(String, String)>,
    favorites: Vec<Favorite>,
    /// お気に入り登録ダイアログ: 入力中の名前 (Some の間だけ表示)
    fav_dialog: Option<String>,
    fav_dialog_fresh: bool,
    show_favs: bool,
    /// 一覧を開いた直後のクリックで閉じないための判定用
    fav_shown: bool,
    fav_filter: String,
    /// 名前変更中の (番号, 入力中の名前)
    fav_rename: Option<(usize, String)>,
    /// 削除の確認待ち (もう一度押すと削除)
    fav_confirm_delete: Option<usize>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        setup_style(&cc.egui_ctx);
        migrate_legacy_files();
        let mut app = Self::blank();
        for fl in app.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            fl.state = default_state(fl.label);
        }
        app.load_from_disk();
        app.reload_favorites();
        app.load_settings();
        app.api.load_locked_keys(&ini_path());
        app
    }

    fn blank() -> Self {
        App {
            rng: Rng::new(),
            gender: Some(0),
            age: None,
            count: None,
            appearance: String::new(),
            other: String::new(),
            sections: build_sections(),
            model: 0,
            quality_tags: true,
            output: String::new(),
            output_neg: String::new(),
            output_note: String::new(),
            mj_no_params: true,
            adjust: String::new(),
            negative_input: String::new(),
            negatives: Vec::new(),
            style: 0,
            aspect: 1,
            quality: 1.0,
            chaos: 0.0,
            stylize: 100.0,
            use_seed: false,
            seed: String::new(),
            nav: 0,
            scroll_to: None,
            folded: [false; LAYOUT.len()],
            simple_mode: false,
            copy_mode: 0,
            scroll: [0.0; 2],
            scroll_restore: [true; 2],
            api: ApiSettings::default(),
            show_api: false,
            models: Default::default(),
            models_status: String::new(),
            key_status: String::new(),
            models_rx: None,
            api_status: String::new(),
            api_fallback: (String::new(), String::new()),
            api_rx: None,
            api_job: ApiJob::Generate,
            last_saved: String::new(),
            last_save_check: 0.0,
            window: None,
            last_ini: String::new(),
            adjust_fallback: String::new(),
            dict_open: None,
            dict_shown: None,
            dict_filter: String::new(),
            dict_sel: 0,
            dict_file: String::new(),
            show_dicts: false,
            dict_msg: String::new(),
            show_saved: false,
            show_history: false,
            saved: Vec::new(),
            history: Vec::new(),
            favorites: Vec::new(),
            fav_dialog: None,
            fav_dialog_fresh: false,
            show_favs: false,
            fav_shown: false,
            fav_filter: String::new(),
            fav_rename: None,
            fav_confirm_delete: None,
        }
    }

    fn reset(&mut self) {
        self.gender = None;
        self.age = None;
        self.count = None;
        self.appearance.clear();
        self.other.clear();
        for s in &mut self.sections {
            for fl in &mut s.fields {
                fl.state = default_state(fl.label);
            }
        }
    }

    fn randomize_all(&mut self) {
        self.gender = self.rng.opt(3);
        self.age = self.rng.opt(5);
        self.count = self.rng.opt(2);
        self.appearance = random_appearance(&mut self.rng);
        for s in &mut self.sections {
            for fl in s.fields.iter_mut().filter(|fl| !self.simple_mode || fl.simple) {
                fl.randomize(&mut self.rng);
            }
        }
    }

    /// 項目に属さない自由入力を分けて、辞書にある語は英語にする (API利用時は日本語のままAIに渡す)
    fn translate_free(&self, text: &str) -> Vec<String> {
        split_free(text)
            .into_iter()
            .map(|w| if self.api.enabled { w } else { dict::lookup_compound(&[], &w).unwrap_or(w) })
            .collect()
    }

    /// 入力内容から (本文, ネガティブ) を組み立てる。辞書の語は英語、辞書外の自由入力は入力のまま
    fn collect(&self) -> (String, String) {
        let mut parts: Vec<String> = Vec::new();
        if let Some(c) = self.count {
            parts.push(count_tag(c, self.gender));
        }
        if let Some(g) = self.gender {
            parts.push(GENDER_TAGS[g].to_string());
        }
        if let Some(a) = self.age {
            parts.push(AGE_TAGS[a].to_string());
        }
        parts.extend(self.translate_free(&self.appearance));
        for s in &self.sections {
            for fl in &s.fields {
                parts.extend(fl.prompt_terms(!self.api.enabled));
            }
        }
        parts.extend(self.translate_free(&self.other));
        let (parts, moved) = self.split_negations(parts);
        (parts.join(", "), merge_unique(self.negatives.iter().cloned().chain(moved)).join(", "))
    }

    /// 「no background」のような否定の語は、ネガティブプロンプトがあるモデル (Midjourney の --no・Stable Diffusion 系) では
    /// ネガティブ側の「background」にする。ネガティブが無い DALL·E など (自然文) ではそのまま本文に残す。
    /// 戻り値は (本文に残す語, ネガティブへ移した語)
    fn split_negations(&self, terms: Vec<String>) -> (Vec<String>, Vec<String>) {
        if FORMATS[self.model].kind == Kind::Sentence {
            return (terms, Vec::new());
        }
        let mut keep = Vec::new();
        let mut moved = Vec::new();
        for t in terms {
            match negation_target(&t) {
                Some(n) => moved.push(n),
                None => keep.push(t),
            }
        }
        (keep, moved)
    }

    /// クリップボードへ渡す文。先頭に、選んでいるモデル向けの依頼文を付ける (内容が空なら空)
    fn copy_text(&self) -> String {
        let body = self.context_text();
        if body.is_empty() {
            return body;
        }
        format!(
            "貴方は、プロンプトエンジニアです。
以下の内容を英語の「{}」用のプロンプトにしてください

{body}",
            FORMATS[self.model].name
        )
    }

    /// コピー形式に合わせて、選択・入力した内容をテキストにする
    fn context_text(&self) -> String {
        match self.copy_mode {
            1 => self.context_text_en(),
            2 => self.words_text(),
            _ => self.context_text_ja(),
        }
    }

    /// 人数・性別・年齢の英語タグ (人数, 性別, 年齢の順)
    fn basic_tags(&self) -> [Option<String>; 3] {
        [
            self.count.map(|c| count_tag(c, self.gender)),
            self.gender.map(|g| GENDER_TAGS[g].to_string()),
            self.age.map(|a| AGE_TAGS[a].to_string()),
        ]
    }

    /// 英語の単語だけを、分類なしでカンマ区切りに並べる。ネガティブは意味が逆なので、別の行 (Negative prompt: ...) にする
    fn words_text(&self) -> String {
        let mut words: Vec<String> = self.basic_tags().into_iter().flatten().collect();
        words.extend(self.translate_free(&self.appearance));
        for si in LAYOUT.into_iter().flatten() {
            for fl in &self.sections[si].fields {
                words.extend(fl.prompt_terms(true));
            }
        }
        words.extend(self.translate_free(&self.other));
        let (words, moved) = self.split_negations(words);
        let positive = merge_unique(words).join(", ");
        let negatives = merge_unique(self.negatives.iter().cloned().chain(moved));
        match (positive.is_empty(), negatives.is_empty()) {
            (_, true) => positive,
            (true, false) => format!("Negative prompt: {}", negatives.join(", ")),
            (false, false) => format!("{positive}
Negative prompt: {}", negatives.join(", ")),
        }
    }

    /// 見出しも項目名もすべて英語にした、項目ごとのテキスト (英語のAIへの相談・共有用)
    fn context_text_en(&self) -> String {
        let mut blocks: Vec<(&str, Vec<String>)> = Vec::new();
        for item in LAYOUT {
            match item {
                None => {
                    let [count, gender, age] = self.basic_tags();
                    let mut basic = Vec::new();
                    basic.extend(count.map(|t| format!("Count: {t}")));
                    basic.extend(gender.map(|t| format!("Gender: {t}")));
                    basic.extend(age.map(|t| format!("Age: {t}")));
                    if !self.appearance.trim().is_empty() {
                        basic.push(format!("Appearance: {}", self.translate_free(&self.appearance).join(", ")));
                    }
                    blocks.push(("Character", basic));
                }
                Some(si) => {
                    let sec = &self.sections[si];
                    let rows = sec
                        .fields
                        .iter()
                        .filter_map(|fl| {
                            let t = fl.prompt_terms(true);
                            (!t.is_empty()).then(|| format!("{}: {}", en_label(fl.label), t.join(", ")))
                        })
                        .collect();
                    blocks.push((en_label(sec.title), rows));
                }
            }
        }
        let other = self.translate_free(&self.other);
        if !other.is_empty() {
            blocks.push(("Other", vec![other.join(", ")]));
        }
        let mut lines: Vec<String> = Vec::new();
        for (title, rows) in blocks.into_iter().filter(|(_, r)| !r.is_empty()) {
            lines.push(format!("## {title}"));
            lines.extend(rows.into_iter().map(|r| format!("- {r}")));
            lines.push(String::new());
        }
        if !self.negatives.is_empty() {
            lines.push("## Negative".into());
            lines.push(format!("- {}", self.negatives.join(", ")));
            lines.push(String::new());
        }
        if lines.is_empty() {
            return String::new();
        }
        let note = if FORMATS[self.model].kind == Kind::Midjourney && self.mj_no_params {
            "Note: Midjourney: parameters (--ar, --v, etc.) are not needed. Output the prompt body only.\n\n"
        } else {
            ""
        };
        format!("{note}# Selection (target model: {})\n\n{}", FORMATS[self.model].name, lines.join("\n").trim_end())
    }

    /// 選択・入力した内容を、項目ごとに整理したテキストにする (AIへの相談・共有用)
    fn context_text_ja(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut basic = Vec::new();
        if let Some(c) = self.count {
            basic.push(format!(
                "人数: {} ({})",
                COUNTS[c],
                count_tag(c, self.gender)
            ));
        }
        if let Some(g) = self.gender {
            basic.push(format!("性別: {} ({})", GENDERS[g], GENDER_TAGS[g]));
        }
        if let Some(a) = self.age {
            basic.push(format!("年齢: {} ({})", AGES[a], AGE_TAGS[a]));
        }
        if !self.appearance.trim().is_empty() {
            basic.push(format!(
                "外見の特徴: {}",
                split_free(&self.appearance).join(", ")
            ));
        }
        let mut blocks: Vec<(&str, Vec<String>)> = Vec::new();
        for item in LAYOUT {
            match item {
                None => blocks.push(("キャラクター設定", basic.clone())),
                Some(si) => {
                    let sec = &self.sections[si];
                    let rows = sec
                        .fields
                        .iter()
                        .filter_map(|fl| {
                            let t: Vec<String> = fl
                                .prompt_terms(false)
                                .into_iter()
                                .filter(|s| !s.trim().is_empty())
                                .collect();
                            (!t.is_empty()).then(|| format!("{}: {}", fl.label, t.join(", ")))
                        })
                        .collect();
                    blocks.push((sec.title, rows));
                }
            }
        }
        let other = split_free(&self.other);
        if !other.is_empty() {
            blocks.push(("その他", vec![other.join(", ")]));
        }
        for (title, rows) in blocks.into_iter().filter(|(_, r)| !r.is_empty()) {
            lines.push(format!("## {title}"));
            lines.extend(rows.into_iter().map(|r| format!("- {r}")));
            lines.push(String::new());
        }
        if !self.negatives.is_empty() {
            lines.push("## ネガティブ".into());
            lines.push(format!("- {}", self.negatives.join(", ")));
            lines.push(String::new());
        }
        if lines.is_empty() {
            return String::new();
        }
        let note = if FORMATS[self.model].kind == Kind::Midjourney && self.mj_no_params {
            "※ Midjourney: パラメータ (--ar, --v など) は不要です。プロンプト本文のみ出力してください。

"
        } else {
            ""
        };
        format!(
            "{note}# 選択内容 (出力モデル: {})

{}",
            FORMATS[self.model].name,
            lines
                .join(
                    "
"
                )
                .trim_end()
        )
    }

    /// 生成ボタン。API英語化が有効で日本語が残っている場合は、LLM APIで英語にしてから出力する
    fn generate(&mut self, ctx: &egui::Context) {
        let (body, neg) = self.collect();
        // API有効なら、選択内容をAIに渡して対象モデル向けのプロンプトを作らせる
        if !self.api.enabled || (body.is_empty() && neg.is_empty()) {
            self.api_status.clear();
            self.finish(body, neg);
            return;
        }
        if self.api_rx.is_some() {
            self.api_status = "AIに依頼中です。終わるまでお待ちください".into();
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.api_rx = Some(rx);
        self.api_job = ApiJob::Generate;
        self.api_status = format!(
            "LLM APIで{}向けのプロンプトを作成しています…",
            FORMATS[self.model].name
        );
        self.api_fallback = (body.clone(), neg.clone());
        let api = self.api.clone();
        let idx = self.model;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(llm_generate(&api, &FORMATS[idx], &body, &neg));
            ctx.request_repaint();
        });
    }

    fn refresh_models(&mut self, ctx: &egui::Context) {
        if self.models_rx.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.models_rx = Some(rx);
        self.models_status = "モデル一覧を取得しています…".into();
        let api = self.api.clone();
        let idx = api.provider.index();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send((idx, fetch_models(&api)));
            ctx.request_repaint();
        });
    }

    /// 「調整」ボタン。API有効なら、ポジティブ・ネガティブ・調整内容をAIに渡し、修正後のポジティブ/ネガティブを
    /// それぞれの欄に振り分ける。無効なら(または出力が空なら)、調整内容をそのままポジティブの末尾に追加する
    fn adjust(&mut self, ctx: &egui::Context) {
        let instr = self.adjust.trim().to_string();
        if instr.is_empty() {
            self.api_status = "調整内容を入力してください".into();
            return;
        }
        if self.api_rx.is_some() {
            return;
        }
        let local = if self.output.trim().is_empty() {
            instr.clone()
        } else {
            format!("{}, {instr}", self.output.trim_end().trim_end_matches(','))
        };
        if !self.api.enabled || (self.output.trim().is_empty() && self.output_neg.trim().is_empty())
        {
            self.output = local;
            self.adjust.clear();
            self.api_status.clear();
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.api_rx = Some(rx);
        self.api_job = ApiJob::Adjust;
        self.api_status = "LLM APIで修正しています…".into();
        self.adjust_fallback = local;
        let api = self.api.clone();
        let idx = self.model;
        let (pos, neg) = (self.output.clone(), self.output_neg.clone());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(llm_adjust(&api, &FORMATS[idx], &pos, &neg, &instr));
            ctx.request_repaint();
        });
    }

    fn poll_models(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.models_rx else { return };
        match rx.try_recv() {
            Ok((idx, Ok(list))) => {
                self.models_rx = None;
                self.models_status = format!("{}件のモデルを取得しました", list.len());
                self.models[idx] = list;
            }
            Ok((_, Err(e))) => {
                self.models_rx = None;
                self.models_status = format!("取得失敗: {e}");
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100))
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.models_rx = None,
        }
    }

    fn poll_api(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.api_rx else { return };
        match rx.try_recv() {
            Ok(Ok((b, n))) => {
                self.api_rx = None;
                if self.api_job == ApiJob::Adjust {
                    // 修正後のポジティブ/ネガティブを、それぞれの欄に振り分ける
                    self.api_status = "LLM APIで修正しました".into();
                    self.output = b;
                    self.output_neg = n;
                    self.adjust.clear();
                } else {
                    self.api_status = format!(
                        "LLM APIで{}向けのプロンプトを作成しました",
                        FORMATS[self.model].name
                    );
                    self.finish(b, n);
                }
            }
            Ok(Err(e)) => {
                self.api_rx = None;
                if self.api_job == ApiJob::Adjust {
                    self.api_status = format!("API失敗: {e} (修正内容をそのまま追加しました)");
                    self.output = std::mem::take(&mut self.adjust_fallback);
                    self.adjust.clear();
                } else {
                    self.api_status = format!("API失敗: {e} (辞書による変換のみで出力しました)");
                    let (b, n) = std::mem::take(&mut self.api_fallback);
                    self.finish(b, n);
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100))
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.api_rx = None,
        }
    }

    fn finish(&mut self, body: String, neg: String) {
        let f = &FORMATS[self.model];
        let aspect = ASPECTS[self.aspect];
        // シードは数字のときだけ使う (Midjourney等は数字以外を受け付けない)
        let seed = Some(self.seed.trim())
            .filter(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or("");
        // 辞書のタグは snake_case なので、プロンプトでは空白区切りにする (品質タグの score_ 等はこのあと付ける)
        let prefix = if self.quality_tags { f.prefix } else { "" };
        let body = if f.kind == Kind::Webui {
            compose_positive(prefix, &body)
        } else {
            let body = body.replace('_', " ");
            match (prefix.is_empty(), body.is_empty()) {
                (true, _) => body,
                (false, true) => prefix.to_string(),
                (false, false) => format!("{prefix}, {body}"),
            }
        };
        let neg = compose_negative(if self.quality_tags { f.neg } else { "" }, &neg);
        self.output_note.clear();
        match f.kind {
            Kind::Midjourney => {
                // パラメータ情報が不要な場合は本文のみ。必要な場合は /imagine とパラメータを付ける
                // ネガティブは、ユーザーが入力したときだけ出る (MJ用の既定ネガティブは無い)
                if self.mj_no_params {
                    self.output = body;
                } else {
                    let mut s = format!(
                        "/imagine prompt:\n{body}\n--ar {aspect} --v 6.1 --style {}",
                        STYLES[self.style]
                    );
                    if !neg.is_empty() {
                        s += &format!(" --no {neg}");
                    }
                    if self.chaos > 0.0 {
                        s += &format!(" --chaos {}", self.chaos as i32);
                    }
                    s += &format!(" --stylize {}", self.stylize as i32);
                    if self.quality != 1.0 {
                        s += &format!(" --q {}", self.quality);
                    }
                    if self.use_seed && !seed.is_empty() {
                        s += &format!(" --seed {seed}");
                    }
                    self.output = s;
                }
                self.output_neg = neg;
            }
            Kind::Sentence | Kind::Webui => {
                self.output = body;
                self.output_neg = neg;
                let size = if f.kind == Kind::Webui {
                    format!("推奨サイズ {} ({aspect})", SIZES[self.aspect])
                } else {
                    format!("アスペクト比 {aspect}")
                };
                self.output_note = if self.use_seed && !seed.is_empty() {
                    format!("{size} / Seed {seed}")
                } else {
                    size
                };
            }
        }
        self.history
            .insert(0, (self.output.clone(), self.output_neg.clone()));
        self.history.truncate(50);
    }

    /// 「お気に入りに追加」: 今のポジティブ/ネガティブを名前付きで登録する (新しいものが先頭)
    fn add_favorite(&mut self, name: &str) -> Result<(), String> {
        if self.output.trim().is_empty() && self.output_neg.trim().is_empty() {
            return Err("登録できるプロンプトがありません".into());
        }
        let name: String = name.trim().chars().take(60).collect();
        let name = if name.is_empty() {
            format!("お気に入り {}", self.favorites.len() + 1)
        } else {
            name
        };
        self.favorites.insert(
            0,
            Favorite {
                name,
                positive: self.output.clone(),
                negative: self.output_neg.clone(),
                model: FORMATS[self.model].name.to_string(),
                file: String::new(),
            },
        );
        self.favorites.truncate(MAX_FAVORITES);
        Ok(())
    }

    /// Fav フォルダと突き合わせる: MD未保存のもの(旧版のstate.json分)を書き出し、フォルダの内容を一覧にする。
    /// フォルダに手で置いた・編集した・消したMDもここで反映される
    fn reload_favorites(&mut self) {
        let dir = fav_dir();
        let mut unsaved = Vec::new();
        for mut f in std::mem::take(&mut self.favorites) {
            if f.file.is_empty() && fav_write(&dir, &mut f).is_err() {
                f.file.clear();
                unsaved.push(f);
            }
        }
        match fav_scan(&dir) {
            Some(mut list) => {
                list.extend(unsaved);
                list.truncate(MAX_FAVORITES);
                self.favorites = list;
            }
            None => self.favorites = unsaved,
        }
    }

    /// 追加したお気に入り(先頭)をMDファイルに保存する
    fn save_new_favorite(&mut self) -> Result<(), String> {
        let f = self.favorites.first_mut().ok_or("お気に入りがありません")?;
        fav_write(&fav_dir(), f).map_err(|e| format!("Favフォルダへの保存に失敗しました: {e}"))
    }

    /// お気に入りを出力欄に呼び出す (出力モデルも戻す)
    fn recall_favorite(&mut self, i: usize) {
        let Some(f) = self.favorites.get(i).cloned() else {
            return;
        };
        self.output = f.positive;
        self.output_neg = f.negative;
        self.output_note.clear();
        if let Some(idx) = FORMATS.iter().position(|x| x.name == f.model) {
            self.model = idx;
        }
        self.api_status = format!("お気に入り「{}」を呼び出しました", f.name);
    }

    fn snapshot(&self, name: String) -> Saved {
        Saved {
            name,
            gender: self.gender,
            age: self.age,
            count: self.count,
            appearance: self.appearance.clone(),
            other: self.other.clone(),
            values: self
                .sections
                .iter()
                .map(|s| s.fields.iter().map(|f| f.state.clone()).collect())
                .collect(),
        }
    }

    fn restore(&mut self, s: &Saved) {
        self.gender = s.gender;
        self.age = s.age;
        self.count = s.count;
        self.appearance = s.appearance.clone();
        self.other = s.other.clone();
        for (sec, vals) in self.sections.iter_mut().zip(&s.values) {
            for (fl, v) in sec.fields.iter_mut().zip(vals) {
                fl.state = v.clone();
            }
        }
    }
}

/// お気に入りのMDファイルの保存先: 実行ファイルと同じフォルダの Fav
fn fav_dir() -> std::path::PathBuf {
    data_dir().join("Fav")
}

/// 内容に含まれる ``` と衝突しない長さのコードフェンス
fn fav_fence(s: &str) -> String {
    let (mut run, mut max) = (0usize, 0usize);
    for c in s.chars() {
        if c == '`' {
            run += 1;
            max = max.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(max.max(2) + 1)
}

/// お気に入りを Markdown にする
fn fav_render(f: &Favorite) -> String {
    let block = |s: &str| {
        let fence = fav_fence(s);
        format!("{fence}text\n{s}\n{fence}\n")
    };
    format!(
        "# {}\n\n- モデル: {}\n\n## ポジティブ\n\n{}\n## ネガティブ\n\n{}",
        f.name.replace(['\r', '\n'], " "),
        f.model.replace(['\r', '\n'], " "),
        block(&f.positive),
        block(&f.negative)
    )
}

/// Markdown からお気に入りを読む。形式が多少崩れていても読めるものは読む (名前が無ければ fallback_name)
fn fav_parse(text: &str, fallback_name: &str) -> Favorite {
    let (mut name, mut model) = (String::new(), String::new());
    let mut fenced: [Option<String>; 2] = [None, None];
    let mut plain: [Vec<&str>; 2] = [Vec::new(), Vec::new()];
    let mut sec: Option<usize> = None;
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim_end();
        let t = l.trim();
        if let Some(rest) = l.strip_prefix("## ") {
            sec = match rest.trim() {
                "ポジティブ" => Some(0),
                "ネガティブ" => Some(1),
                _ => None,
            };
        } else if let Some(s) = sec {
            let n = t.chars().take_while(|&c| c == '`').count();
            if n >= 3 && fenced[s].is_none() {
                let mut body = Vec::new();
                i += 1;
                while i < lines.len() {
                    let c = lines[i].trim();
                    if c.len() >= n && c.chars().all(|ch| ch == '`') {
                        break;
                    }
                    body.push(lines[i].trim_end_matches('\r'));
                    i += 1;
                }
                fenced[s] = Some(body.join("\n"));
            } else {
                plain[s].push(l);
            }
        } else if let Some(rest) = l.strip_prefix("# ") {
            if name.is_empty() {
                name = rest.trim().to_string();
            }
        } else if let Some(rest) = t
            .strip_prefix("- モデル")
            .map(|r| r.trim_start_matches([':', '：']))
        {
            model = rest.trim().to_string();
        }
        i += 1;
    }
    let pick = |k: usize| fenced[k].take_or_plain(&plain[k]);
    let name: String = if name.is_empty() {
        fallback_name.to_string()
    } else {
        name
    }
    .chars()
    .take(60)
    .collect();
    Favorite {
        name,
        positive: pick(0),
        negative: pick(1),
        model,
        file: String::new(),
    }
}

trait TakeOrPlain {
    fn take_or_plain(&self, plain: &[&str]) -> String;
}

impl TakeOrPlain for Option<String> {
    fn take_or_plain(&self, plain: &[&str]) -> String {
        match self {
            Some(s) => s.clone(),
            None => plain.join("\n").trim().to_string(),
        }
    }
}

/// ファイル名に使えない文字などを除き、Windowsの予約名も避ける
fn fav_file_stem(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "\\/:*?\"<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .take(40)
        .collect();
    let s = s.trim().trim_matches('.').trim().to_string();
    let upper = s.to_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&upper.as_str())
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit());
    if s.is_empty() {
        "fav".into()
    } else if reserved {
        format!("_{s}")
    } else {
        s
    }
}

/// Fav フォルダ直下の安全な .md ファイル名か (パス区切りや .. を含めない)
fn fav_file_ok(file: &str) -> bool {
    !file.is_empty()
        && file.ends_with(".md")
        && std::path::Path::new(file)
            .file_name()
            .is_some_and(|n| n == std::ffi::OsStr::new(file))
        && !file.contains(['\\', '/', ':'])
}

/// MDファイルへ書き出す。file が空なら名前から重複しないファイル名を決める (一時ファイル経由で書き換える)
fn fav_write(dir: &std::path::Path, f: &mut Favorite) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if !fav_file_ok(&f.file) {
        let stem = fav_file_stem(&f.name);
        let mut file = format!("{stem}.md");
        let mut n = 2;
        while dir.join(&file).exists() {
            file = format!("{stem} ({n}).md");
            n += 1;
            if n > 10_000 {
                return Err(std::io::Error::other("ファイル名を決められません"));
            }
        }
        f.file = file;
    }
    let path = dir.join(&f.file);
    let tmp = dir.join(format!("{}.tmp", f.file));
    std::fs::write(&tmp, fav_render(f))?;
    std::fs::rename(&tmp, &path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// 対応するMDファイルを削除する (無ければ何もしない)
fn fav_delete(dir: &std::path::Path, f: &Favorite) {
    if fav_file_ok(&f.file) {
        let _ = std::fs::remove_file(dir.join(&f.file));
    }
}

/// Fav フォルダの .md を新しい順に読む。フォルダが無ければ空、読めなければ None
fn fav_scan(dir: &std::path::Path) -> Option<Vec<Favorite>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut items: Vec<(std::time::SystemTime, Favorite)> = Vec::new();
    for e in rd.flatten() {
        let file = e.file_name().to_string_lossy().to_string();
        if !fav_file_ok(&file) || !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Some(text) = read_text_limited(&e.path(), 1 << 20) else {
            continue;
        };
        let stem = file.trim_end_matches(".md").to_string();
        let mut fav = fav_parse(&text, &stem);
        if fav.positive.trim().is_empty() && fav.negative.trim().is_empty() {
            continue;
        }
        fav.file = file;
        let mtime = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        items.push((mtime, fav));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.file.cmp(&b.1.file)));
    items.truncate(MAX_FAVORITES);
    Some(items.into_iter().map(|(_, f)| f).collect())
}

/// 作業中の内容の保存先 (設定INIと同じフォルダの state.json)。APIキーは保存しない
fn state_path() -> std::path::PathBuf {
    data_dir().join("state.json")
}

fn state_to_json(s: &FieldState) -> serde_json::Value {
    serde_json::json!({
        "tokens": s.tokens.iter().map(|t| serde_json::json!({"ja": t.ja, "en": t.en})).collect::<Vec<_>>(),
        "free": s.free,
    })
}

fn state_from_json(v: &serde_json::Value) -> FieldState {
    FieldState {
        tokens: v["tokens"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| {
                        Some(Tok {
                            ja: t["ja"].as_str()?.into(),
                            en: t["en"].as_str()?.into(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        free: v["free"].as_str().unwrap_or("").into(),
    }
}

fn field_key(sec: &Section, fl: &Field) -> String {
    format!("{}/{}", sec.title, fl.label)
}

fn opt_index(v: &serde_json::Value, len: usize) -> Option<usize> {
    v.as_u64().map(|x| x as usize).filter(|x| *x < len)
}

impl App {
    /// 「保存した設定」の1件をJSONにする (項目は 分類/項目名 をキーにして、項目の増減に強くする)
    fn saved_to_json(&self, s: &Saved) -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        for (sec, vals) in self.sections.iter().zip(&s.values) {
            for (fl, st) in sec.fields.iter().zip(vals) {
                fields.insert(field_key(sec, fl), state_to_json(st));
            }
        }
        serde_json::json!({"name": s.name, "gender": s.gender, "age": s.age, "count": s.count, "appearance": s.appearance, "other": s.other, "fields": fields})
    }

    fn saved_from_json(&self, v: &serde_json::Value) -> Saved {
        let values = self
            .sections
            .iter()
            .map(|sec| {
                sec.fields
                    .iter()
                    .map(|fl| state_from_json(&v["fields"][field_key(sec, fl)]))
                    .collect()
            })
            .collect();
        Saved {
            name: v["name"].as_str().unwrap_or("設定").into(),
            gender: opt_index(&v["gender"], GENDERS.len()),
            age: opt_index(&v["age"], AGES.len()),
            count: opt_index(&v["count"], COUNTS.len()),
            appearance: v["appearance"].as_str().unwrap_or("").into(),
            other: v["other"].as_str().unwrap_or("").into(),
            values,
        }
    }

    /// 作業中の内容 (入力・出力・保存した設定・履歴)。設定(位置・オプション・API)は settings.ini に保存する
    fn to_json(&self) -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        for sec in &self.sections {
            for fl in &sec.fields {
                fields.insert(field_key(sec, fl), state_to_json(&fl.state));
            }
        }
        serde_json::json!({
            "version": 1,
            "default_tokens": 1,
            "gender": self.gender, "age": self.age, "count": self.count, "appearance": self.appearance, "other": self.other, "fields": fields,
            "negatives": self.negatives, "negative_input": self.negative_input, "adjust": self.adjust,
            "output": self.output, "output_neg": self.output_neg, "output_note": self.output_note,
            "saved": self.saved.iter().map(|s| self.saved_to_json(s)).collect::<Vec<_>>(),
            "history": self.history.iter().take(50).map(|(p, n)| serde_json::json!([p, n])).collect::<Vec<_>>(),
            "favorites": self.favorites.iter().filter(|f| f.file.is_empty()).map(|f| serde_json::json!({"name": f.name, "positive": f.positive, "negative": f.negative, "model": f.model})).collect::<Vec<_>>(),
        })
    }

    fn load_json(&mut self, v: &serde_json::Value) {
        let text = |k: &str| v[k].as_str().unwrap_or("").to_string();
        self.gender = opt_index(&v["gender"], GENDERS.len());
        self.age = opt_index(&v["age"], AGES.len());
        self.count = opt_index(&v["count"], COUNTS.len());
        self.appearance = text("appearance");
        self.other = text("other");
        for sec in &mut self.sections {
            for fl in &mut sec.fields {
                let saved = &v["fields"][format!("{}/{}", sec.title, fl.label)];
                // 保存データに項目が無い (古いデータ) ときは、最初から入れる語を使う
                fl.state = if saved.is_null() { default_state(fl.label) } else { state_from_json(saved) };
                // 既定の語を入れる前に保存されたデータ: 空の項目には一度だけ既定の語を入れる (以後は削除したまま保たれる)
                if v["default_tokens"].is_null() && fl.state.tokens.is_empty() && fl.state.free.is_empty() {
                    fl.state.tokens = default_state(fl.label).tokens;
                }
            }
        }
        self.negatives = v["negatives"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        self.negative_input = text("negative_input");
        self.adjust = text("adjust");
        self.output = text("output");
        self.output_neg = text("output_neg");
        self.output_note = text("output_note");
        self.model = opt_index(&v["model"], FORMATS.len()).unwrap_or(0);
        self.quality_tags = v["quality_tags"].as_bool().unwrap_or(true);
        self.mj_no_params = v["mj_no_params"].as_bool().unwrap_or(true);
        self.aspect = opt_index(&v["aspect"], ASPECTS.len()).unwrap_or(1);
        self.style = opt_index(&v["style"], STYLES.len()).unwrap_or(0);
        self.quality = v["quality"].as_f64().unwrap_or(1.0) as f32;
        self.chaos = v["chaos"].as_f64().unwrap_or(0.0) as f32;
        self.stylize = v["stylize"].as_f64().unwrap_or(100.0) as f32;
        self.use_seed = v["use_seed"].as_bool().unwrap_or(false);
        self.seed = text("seed");
        self.api.enabled = v["api"]["enabled"].as_bool().unwrap_or(false);
        if let Some(i) = opt_index(&v["api"]["provider"], 3) {
            self.api.provider = Provider::ALL[i];
        }
        for (i, c) in self.api.cfg.iter_mut().enumerate() {
            let s = &v["api"]["cfg"][i];
            if let Some(u) = s["base_url"].as_str().filter(|x| !x.is_empty()) {
                c.base_url = u.into();
            }
            if let Some(mo) = s["model"].as_str().filter(|x| !x.is_empty()) {
                c.model = mo.into();
            }
        }
        self.saved = v["saved"]
            .as_array()
            .map(|a| a.iter().map(|s| self.saved_from_json(s)).collect())
            .unwrap_or_default();
        self.history = v["history"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|h| {
                        (
                            h[0].as_str().unwrap_or("").to_string(),
                            h[1].as_str().unwrap_or("").to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.favorites = v["favorites"]
            .as_array()
            .map(|a| {
                a.iter()
                    .take(MAX_FAVORITES)
                    .map(|f| Favorite {
                        name: f["name"].as_str().unwrap_or("お気に入り").to_string(),
                        positive: f["positive"].as_str().unwrap_or("").to_string(),
                        negative: f["negative"].as_str().unwrap_or("").to_string(),
                        model: f["model"].as_str().unwrap_or("").to_string(),
                        file: String::new(),
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    fn load_from_disk(&mut self) {
        if let Some(text) = read_text_limited(&state_path(), 50 << 20) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                self.load_json(&v);
                self.last_saved = self.to_json().to_string();
            }
        }
    }

    fn save_to_disk(&mut self) {
        let s = self.to_json().to_string();
        if s == self.last_saved {
            return;
        }
        let path = state_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // 書き込み途中で落ちても壊れないよう、一時ファイル経由で置き換える
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &s).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            self.last_saved = s;
        }
    }

    /// 約1秒ごとに変更を確認して自動保存する。変更後に操作が止まっても保存されるよう、再描画を予約する
    /// 設定(ウィンドウ位置・出力モデルなどのオプション・API設定)を INI のマップにする。
    /// `base` は既存のINI内容 (暗号化キーなど、このメソッドが触らない項目を引き継ぐ)
    fn settings_to_map(
        &self,
        base: std::collections::BTreeMap<String, String>,
    ) -> std::collections::BTreeMap<String, String> {
        let mut map = base;
        let mut put = |k: &str, v: String| {
            map.insert(k.to_string(), v.replace(['\n', '\r'], " "));
        };
        if let Some([x, y, w, h]) = self.window {
            put("window.x", x.to_string());
            put("window.y", y.to_string());
            put("window.width", w.to_string());
            put("window.height", h.to_string());
        }
        put("dictionary.file", self.dict_file.clone());
        put("ui.scroll_left", self.scroll[0].round().to_string());
        put("ui.scroll_right", self.scroll[1].round().to_string());
        put("ui.folded", self.folded.iter().map(|b| if *b { '1' } else { '0' }).collect());
        put("ui.copy_mode", self.copy_mode.to_string());
        put("ui.mode", if self.simple_mode { "simple" } else { "detail" }.to_string());
        put("options.model", FORMATS[self.model].name.to_string());
        put("options.quality_tags", self.quality_tags.to_string());
        put("options.mj_no_params", self.mj_no_params.to_string());
        put("options.aspect", ASPECTS[self.aspect].to_string());
        put("options.style", STYLES[self.style].to_string());
        put("options.quality", self.quality.to_string());
        put("options.chaos", self.chaos.to_string());
        put("options.stylize", self.stylize.to_string());
        put("options.use_seed", self.use_seed.to_string());
        put("options.seed", self.seed.clone());
        put("api.enabled", self.api.enabled.to_string());
        put(
            "api.provider",
            PROVIDER_IDS[self.api.provider.index()].to_string(),
        );
        for (i, c) in self.api.cfg.iter().enumerate() {
            put(
                &format!("api.{}_base_url", PROVIDER_IDS[i]),
                c.base_url.clone(),
            );
            put(&format!("api.{}_model", PROVIDER_IDS[i]), c.model.clone());
        }
        map
    }

    /// INIにある項目だけを反映する (無い項目は現在の値のまま)
    fn settings_from_map(&mut self, map: &std::collections::BTreeMap<String, String>) {
        let get = |k: &str| map.get(k).map(String::as_str);
        let num = |k: &str| get(k).and_then(|v| v.parse::<f32>().ok());
        let flag = |k: &str| get(k).and_then(|v| v.parse::<bool>().ok());
        if let (Some(x), Some(y), Some(w), Some(h)) = (
            num("window.x"),
            num("window.y"),
            num("window.width"),
            num("window.height"),
        ) {
            self.window = Some([x, y, w, h]);
        }
        if let Some(i) = get("options.model").and_then(|n| FORMATS.iter().position(|f| f.name == n))
        {
            self.model = i;
        }
        for (i, k) in ["ui.scroll_left", "ui.scroll_right"].into_iter().enumerate() {
            if let Some(v) = num(k).filter(|v| v.is_finite()) {
                self.scroll[i] = v.max(0.0);
            }
        }
        if let Some(s) = get("ui.folded") {
            for (b, c) in self.folded.iter_mut().zip(s.chars()) {
                *b = c == '1';
            }
        }
        if let Some(v) = num("ui.copy_mode") {
            self.copy_mode = (v as usize).min(COPY_MODES.len() - 1);
        }
        if let Some(v) = get("ui.mode") {
            self.simple_mode = v == "simple";
        }
        if let Some(f) = get("dictionary.file") {
            self.dict_file = f.to_string();
        }
        if let Some(v) = flag("options.quality_tags") {
            self.quality_tags = v;
        }
        if let Some(v) = flag("options.mj_no_params") {
            self.mj_no_params = v;
        }
        if let Some(i) = get("options.aspect").and_then(|n| ASPECTS.iter().position(|a| *a == n)) {
            self.aspect = i;
        }
        if let Some(i) = get("options.style").and_then(|n| STYLES.iter().position(|a| *a == n)) {
            self.style = i;
        }
        if let Some(v) = num("options.quality") {
            self.quality = v;
        }
        if let Some(v) = num("options.chaos") {
            self.chaos = v;
        }
        if let Some(v) = num("options.stylize") {
            self.stylize = v;
        }
        if let Some(v) = flag("options.use_seed") {
            self.use_seed = v;
        }
        if let Some(v) = get("options.seed") {
            self.seed = v.to_string();
        }
        if let Some(v) = flag("api.enabled") {
            self.api.enabled = v;
        }
        if let Some(i) = get("api.provider").and_then(|n| PROVIDER_IDS.iter().position(|p| *p == n))
        {
            self.api.provider = Provider::ALL[i];
        }
        for (i, c) in self.api.cfg.iter_mut().enumerate() {
            if let Some(u) =
                get(&format!("api.{}_base_url", PROVIDER_IDS[i])).filter(|x| !x.is_empty())
            {
                c.base_url = u.to_string();
            }
            if let Some(mo) =
                get(&format!("api.{}_model", PROVIDER_IDS[i])).filter(|x| !x.is_empty())
            {
                c.model = mo.to_string();
            }
        }
    }

    fn load_settings(&mut self) {
        let map = ini_read(&ini_path());
        self.settings_from_map(&map);
        self.apply_dictionary();
        self.last_ini = ini_render(&self.settings_to_map(map));
    }

    /// 使う辞書を読み込む。Dict/dictionary.json が無ければ同梱の初期辞書から作り直す。
    /// 選んだファイルが読めなければ dictionary.json、それも駄目なら同梱の初期辞書を使い、理由を dict_msg に残す
    fn apply_dictionary(&mut self) {
        self.dict_sel = 0;
        let dir = dict_dir();
        let main = dir.join(DEFAULT_DICT);
        if !main.exists() {
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(&main, dict::SEED);
        }
        if self.dict_file.is_empty() {
            self.dict_file = DEFAULT_DICT.to_string();
        }
        let load = |name: &str| -> Result<Vec<dict::Category>, String> {
            if !dict_file_ok(name) {
                return Err("ファイル名が不正です".into());
            }
            read_text_limited(&dir.join(name), 8 << 20)
                .ok_or_else(|| "ファイルを読めません (8MB以下のUTF-8のJSONにしてください)".to_string())
                .and_then(|t| dict::parse_file(name, &t))
        };
        let mut note = String::new();
        let cats = match load(&self.dict_file) {
            Ok(c) => c,
            Err(e) => {
                note = format!("辞書「{}」を使えません: {e}。", self.dict_file);
                self.dict_file = DEFAULT_DICT.to_string();
                match load(DEFAULT_DICT) {
                    Ok(c) => c,
                    Err(e2) => {
                        note += &format!("{DEFAULT_DICT} も使えないため、同梱の初期辞書を使います: {e2}");
                        dict::parse(dict::SEED).unwrap_or_default()
                    }
                }
            }
        };
        dict::set_active(cats);
        self.dict_msg = if note.is_empty() { format!("辞書「{}」を読み込みました", self.dict_file) } else { note };
    }

    /// 辞書の切り替えウィンドウ
    fn dicts_window(&mut self, ctx: &egui::Context) {
        let mut show = self.show_dicts;
        let mut choose: Option<String> = None;
        let mut export = false;
        let mut open_folder = false;
        egui::Window::new("辞書の切り替え").open(&mut show).default_width(460.0).show(ctx, |ui| {
            ui.label(RichText::new(format!("辞書は {} の .json または .rs ファイルです。メモ帳などで編集して「再読み込み」を押すと反映されます。ファイルを選ぶと、その内容だけが辞書になります。", dict_dir().display())).small().color(SUB));
            ui.add_space(4.0);
            let files = dict_files();
            for f in &files {
                if ui.radio(self.dict_file == *f, f).clicked() {
                    choose = Some(f.clone());
                }
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("再読み込み").clicked() {
                    choose = Some(self.dict_file.clone());
                }
                if ui.button("Dictフォルダを開く").clicked() {
                    open_folder = true;
                }
                if ui.button("初期の辞書を書き出す").on_hover_text("同梱の初期辞書を、別名のJSONとして Dict フォルダに作ります (元に戻したいとき・新しい辞書の元にしたいとき)").clicked() {
                    export = true;
                }
            });
            if !self.dict_msg.is_empty() {
                ui.label(RichText::new(&self.dict_msg).small().color(SUB));
            }
        });
        self.show_dicts = show;
        if let Some(f) = choose {
            self.dict_file = f;
            self.apply_dictionary();
        }
        if export {
            let dir = dict_dir();
            let mut n = 1;
            let mut name = "dictionary_initial.json".to_string();
            while dir.join(&name).exists() {
                n += 1;
                name = format!("dictionary_initial ({n}).json");
            }
            self.dict_msg = match std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(&name), dict::SEED)) {
                Ok(()) => format!("{name} を書き出しました"),
                Err(e) => format!("書き出せませんでした: {e}"),
            };
        }
        if open_folder {
            let dir = dict_dir();
            let _ = std::fs::create_dir_all(&dir);
            #[cfg(windows)]
            let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
        }
    }

    /// 設定が変わっていれば settings.ini に書く (既存の暗号化キーなどは保持)
    fn save_settings(&mut self) {
        let path = ini_path();
        let map = self.settings_to_map(ini_read(&path));
        if ini_render(&map) != self.last_ini && ini_write(&path, &map).is_ok() {
            self.last_ini = ini_render(&map);
        }
    }

    /// 通常状態(最小化・最大化・全画面でない)のときだけ、ウィンドウの位置とサイズを控える
    fn track_window(&mut self, ctx: &egui::Context) {
        let vp = ctx.input(|i| i.viewport().clone());
        if vp.minimized == Some(true) || vp.maximized == Some(true) || vp.fullscreen == Some(true) {
            return;
        }
        if let (Some(outer), Some(inner)) = (vp.outer_rect, vp.inner_rect) {
            let w = [outer.min.x, outer.min.y, inner.width(), inner.height()];
            if w.iter().all(|v| v.is_finite()) {
                self.window = Some(w);
            }
        }
    }

    fn autosave(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);
        if now - self.last_save_check >= 1.0 {
            self.last_save_check = now;
            self.save_to_disk();
            self.save_settings();
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(1100));
    }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    for path in [
        r"C:\Windows\Fonts\YuGothM.ttc",
        r"C:\Windows\Fonts\meiryo.ttc",
        r"C:\Windows\Fonts\msgothic.ttc",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "jp".into(),
                std::sync::Arc::new(FontData::from_owned(bytes)),
            );
            for fam in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts
                    .families
                    .entry(fam)
                    .or_default()
                    .insert(0, "jp".into());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn setup_style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = INPUT;
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = ACCENT;
    let r = CornerRadius::same(6);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.inactive.bg_fill = Color32::from_rgb(20, 30, 62);
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(20, 30, 62);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(34, 48, 96);
    v.widgets.hovered.bg_fill = Color32::from_rgb(34, 48, 96);
    v.widgets.active.weak_bg_fill = ACCENT;
    ctx.set_visuals(v);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
    ui.add_space(6.0);
}

/// 分類の見出し。右端(「ランダム」の列に合わせた位置)に、その分類を全てランダムにするボタンを置く
fn heading_random(
    ui: &mut egui::Ui,
    title: &str,
    note: bool,
    sub: &str,
    folded: &mut bool,
) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        let arrow = if *folded { "▶" } else { "▼" };
        if ui
            .add(egui::Button::new(RichText::new(arrow).small()).frame(false))
            .on_hover_text(if *folded { "開く" } else { "折りたたむ" })
            .clicked()
        {
            *folded = !*folded;
        }
        ui.label(RichText::new(title).strong().size(15.0));
        if note {
            ui.label(RichText::new("(言語指定)").small().color(SUB));
        }
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(DICT_BTN_W + ui.spacing().item_spacing.x);
            clicked = ui
                .add_sized(
                    [100.0, 22.0],
                    egui::Button::new(RichText::new("⟳ 全てランダム").small()),
                )
                .on_hover_text("この分類の全項目をランダムにする")
                .clicked();
        });
    });
    if !sub.is_empty() && !*folded {
        ui.label(RichText::new(sub).small().color(SUB));
    }
    ui.add_space(4.0);
    clicked
}

fn heading(ui: &mut egui::Ui, title: &str, note: bool, sub: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).strong().size(15.0));
        if note {
            ui.label(RichText::new("(言語指定)").small().color(SUB));
        }
    });
    if !sub.is_empty() {
        ui.label(RichText::new(sub).small().color(SUB));
    }
    ui.add_space(4.0);
}

/// 入力欄: ボタン入力の語はチップ(色付き・日本語)で並べ、続けて自由入力欄を置く。
/// チップは区切り文字が無くても別の語として扱う。チップを押すと外せる
fn field_input(ui: &mut egui::Ui, fl: &mut Field, w: f32) {
    egui::Frame::new()
        .fill(INPUT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::same(3))
        .show(ui, |ui| {
            // 枠の内側余白(3x2)と罫線(1x2)を引いた幅を使い切る
            ui.set_width((w - 8.0).max(120.0));
            ui.horizontal_wrapped(|ui| {
                let mut remove = None;
                for (i, t) in fl.state.tokens.iter().enumerate() {
                    let b = egui::Button::new(RichText::new(format!("{} ✕", t.ja)).small())
                        .fill(CHIP)
                        .stroke(Stroke::NONE);
                    if ui
                        .add(b)
                        .on_hover_text(format!("{} (クリックで削除)", t.en))
                        .clicked()
                    {
                        remove = Some(i);
                    }
                }
                if let Some(i) = remove {
                    fl.state.tokens.remove(i);
                }
                let hint = if fl.state.tokens.is_empty() {
                    fl.hint
                } else {
                    "自由入力"
                };
                ui.add(
                    egui::TextEdit::singleline(&mut fl.state.free)
                        .hint_text(hint)
                        .frame(egui::Frame::NONE)
                        .desired_width(ui.available_width().max(120.0)),
                );
            });
        });
}

/// 外見の特徴の例をランダムに選ぶ。空白も選択肢に含む
fn random_appearance(rng: &mut Rng) -> String {
    let samples = ["黒髪で背が高い", "小柄で華奢", "筋肉質で日焼けした肌"];
    rng.opt(samples.len()).map_or(String::new(), |i| samples[i].to_string())
}

/// 「no background」「without hat」のような否定の語から、否定される側 (background / hat) を取り出す。
/// 「no humans」のように、それ自体が1つのタグになっている語は除く
fn negation_target(term: &str) -> Option<String> {
    let t = term.trim();
    let lower = t.to_lowercase();
    if lower == "no humans" {
        return None;
    }
    let rest = ["no ", "without "].iter().find_map(|p| lower.starts_with(p).then(|| t[p.len()..].trim()))?;
    (!rest.is_empty()).then(|| rest.to_string())
}

/// 空の語と、大文字小文字だけが違う重複を除く (最初のものを残す)
fn merge_unique(words: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    words.into_iter().filter(|w| !w.trim().is_empty() && seen.insert(w.trim().to_lowercase())).collect()
}

/// score_6 のような品質スコアのタグか (アンダースコアのまま使い、ネガティブの先頭に置く)
fn is_score_tag(t: &str) -> bool {
    let t = t.trim().to_lowercase();
    t.strip_prefix("score_").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
}

/// 品質スコア・ソースのタグ (score_9, source_anime など)。アンダースコアのまま先頭に置く
fn is_quality_tag(t: &str) -> bool {
    let t = t.trim().to_lowercase();
    is_score_tag(&t) || t.starts_with("source_") || t.starts_with("rating_")
}

/// タグ形式のポジティブを合成する。モデル標準の品質タグを先頭に、本文中の score_*/source_* もその直後に寄せ、
/// それ以外の語の `_` は空白にする。重複は除く
fn compose_positive(prefix: &str, body: &str) -> String {
    let split = |s: &str| -> Vec<String> {
        s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
    };
    let (quality, rest): (Vec<_>, Vec<_>) = split(body).into_iter().partition(|t| is_quality_tag(t));
    let rest = rest.into_iter().map(|t| t.replace('_', " "));
    merge_unique(split(prefix).into_iter().chain(quality).chain(rest)).join(", ")
}

/// モデル標準のネガティブとユーザーのネガティブを合成する。
/// score_* は先頭にまとめ (アンダースコアは保つ)、残りの語の `_` は空白にし、重複は除く
fn compose_negative(model_neg: &str, user_neg: &str) -> String {
    let terms: Vec<String> = model_neg
        .split(',')
        .chain(user_neg.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let (scores, rest): (Vec<_>, Vec<_>) = terms.into_iter().partition(|t| is_score_tag(t));
    let rest = rest.into_iter().map(|t| t.replace('_', " "));
    merge_unique(scores.into_iter().chain(rest)).join(", ")
}

/// ネガティブプロンプト欄の辞書ピッカーを開くときの dict_open の大分類番号
const NEG_PICKER: usize = usize::MAX;

/// いまのネガティブの語を選択済みとして持つ、辞書ピッカー用の仮の項目
fn negative_picker_field(negatives: &[String]) -> Field {
    let mut fl = f("ネガティブプロンプト", "", &[]).dict(&["negative_prompt"]);
    fl.state.tokens = negatives.iter().map(|n| Tok { ja: n.clone(), en: n.clone() }).collect();
    fl
}

fn random_btn(ui: &mut egui::Ui) -> bool {
    ui.add(egui::Button::new(RichText::new("⟳ ランダム").small()).min_size(egui::vec2(72.0, 22.0)))
        .clicked()
}

fn chips(ui: &mut egui::Ui, labels: &[&str], sel: &mut Option<usize>) {
    for (i, l) in labels.iter().enumerate() {
        let on = *sel == Some(i);
        let b = egui::Button::new(RichText::new(*l).small())
            .fill(if on { ACCENT } else { INPUT })
            .min_size(egui::vec2(64.0, 22.0));
        if ui.add(b).clicked() {
            *sel = if on { None } else { Some(i) };
        }
    }
}

impl eframe::App for App {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.save_to_disk();
        self.save_settings();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_api(&ctx);
        self.poll_models(&ctx);
        self.track_window(&ctx);
        self.autosave(&ctx);

        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Prompt Generator").size(24.0).strong());
                ui.label(RichText::new("—  あなたのイメージを、AIの言葉に  —").color(SUB));
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(8.0);
                    let hint = "簡易: 主要な項目だけを表示します。詳細設定: 全ての項目を表示します。
簡易でも、詳細設定で入力した内容はプロンプトに含まれます。";
                    ui.selectable_value(&mut self.simple_mode, false, "詳細設定").on_hover_text(hint);
                    ui.selectable_value(&mut self.simple_mode, true, "簡易").on_hover_text(hint);
                    ui.label(RichText::new("表示:").color(SUB));
                });
            });
            ui.add_space(6.0);
        });

        egui::Panel::left("nav").exact_size(170.0).show(ui, |ui| {
            ui.add_space(8.0);
            for (i, name) in NAV.iter().enumerate() {
                let on = self.nav == i;
                let b = egui::Button::new(RichText::new(*name).size(14.0))
                    .fill(if on { ACCENT } else { Color32::TRANSPARENT })
                    .stroke(Stroke::NONE)
                    .min_size(egui::vec2(ui.available_width(), 38.0));
                if ui.add(b).clicked() {
                    self.nav = i;
                    self.scroll_to = Some(NAV_TARGET[i]);
                }
            }
            ui.with_layout(egui::Layout::bottom_up(Align::Min), |ui| {
                ui.add_space(8.0);
                let w = ui.available_width();
                if ui
                    .add(egui::Button::new("API設定").min_size(egui::vec2(w, 34.0)))
                    .clicked()
                {
                    self.show_api = true;
                }
                if ui
                    .add(egui::Button::new("辞書の切り替え").min_size(egui::vec2(w, 34.0)))
                    .clicked()
                {
                    self.show_dicts = true;
                }
                if ui
                    .add(egui::Button::new("履歴").min_size(egui::vec2(w, 34.0)))
                    .clicked()
                {
                    self.show_history = true;
                }
                if ui
                    .add(egui::Button::new("お気に入り").min_size(egui::vec2(w, 34.0)))
                    .clicked()
                {
                    self.reload_favorites();
                    self.show_favs = true;
                }
                if ui
                    .add(egui::Button::new("保存した設定").min_size(egui::vec2(w, 34.0)))
                    .clicked()
                {
                    self.show_saved = true;
                }
                egui::ComboBox::from_id_salt("preset")
                    .selected_text("プリセット")
                    .width(w - 8.0)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(false, "全項目ランダム").clicked() {
                            self.randomize_all();
                        }
                        if ui.selectable_label(false, "リセット").clicked() {
                            self.reset();
                        }
                    });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            // 入力欄を広く取るため、左(入力)を右(出力)より広くする
            let avail = ui.available_width() - 12.0;
            let (left_w, right_w) = (avail * 0.58, avail * 0.42);
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(left_w, ui.available_height()),
                    egui::Layout::top_down(Align::Min),
                    |ui| {
                        self.left_column(ui);
                    },
                );
                ui.allocate_ui_with_layout(
                    egui::vec2(right_w, ui.available_height()),
                    egui::Layout::top_down(Align::Min),
                    |ui| {
                        self.right_column(ui);
                    },
                );
            });
        });

        self.dict_window(&ctx);
        self.dicts_window(&ctx);
        self.fav_dialog_window(&ctx);
        self.favorites_window(&ctx);

        let mut show = self.show_api;
        egui::Window::new("API設定").open(&mut show).default_width(440.0).show(&ctx, |ui| {
            ui.label(RichText::new("「プロンプトを生成」「調整する」でAIに依頼し、選んだモデルに合った英語のプロンプトだけを受け取って、ポジティブ／ネガティブに振り分けます。").small().color(SUB));
            ui.checkbox(&mut self.api.enabled, "生成・修正時にLLM APIを使う");
            ui.horizontal(|ui| {
                ui.label("API");
                egui::ComboBox::from_id_salt("provider").selected_text(self.api.provider.name()).show_ui(ui, |ui| {
                    for p in Provider::ALL {
                        ui.selectable_value(&mut self.api.provider, p, p.name());
                    }
                });
            });
            let idx = self.api.provider.index();
            let list = self.models[idx].clone();
            let loading = self.models_rx.is_some();
            let mut refresh = false;
            let mut toggle_lock = false;
            let c = self.api.cur_mut();
            let locked = c.locked;
            egui::Grid::new("api_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("ベースURL");
                ui.add(egui::TextEdit::singleline(&mut c.base_url).desired_width(320.0));
                ui.end_row();
                ui.label("モデル");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut c.model).desired_width(190.0));
                    // 取得済みの一覧から選ぶプルダウン
                    egui::ComboBox::from_id_salt("model_list")
                        .selected_text(if list.is_empty() { "一覧 (未取得)" } else { "一覧から選択" })
                        .width(110.0)
                        .show_ui(ui, |ui| {
                            for id in &list {
                                ui.selectable_value(&mut c.model, id.clone(), id);
                            }
                        });
                    // 更新マーク: サーバーへ問い合わせて、現在使えるモデル一覧を取得する
                    if ui.add_enabled(!loading, egui::Button::new("⟳")).on_hover_text("サーバーから利用できるモデル一覧を取得").clicked() {
                        refresh = true;
                    }
                });
                ui.end_row();
                ui.label("APIキー");
                ui.horizontal(|ui| {
                    // ロック中は無効化(グレーアウト)され、選択・コピー・編集を受け付けない
                    ui.add_enabled(!locked, egui::TextEdit::singleline(&mut c.key).password(true).desired_width(220.0));
                    let label = if locked { "ロック解除" } else { "ロック" };
                    if ui.add_sized([86.0, 22.0], egui::Button::new(label)).on_hover_text(if locked { "解除すると保存したキーを削除します" } else { "キーを暗号化してINIに保存し、入力欄をロックします" }).clicked() {
                        toggle_lock = true;
                    }
                });
                ui.end_row();
            });
            if !self.models_status.is_empty() {
                ui.label(RichText::new(&self.models_status).small().color(SUB));
            }
            if !self.key_status.is_empty() {
                ui.label(RichText::new(&self.key_status).small().color(SUB));
            }
            if refresh {
                self.refresh_models(&ctx);
            }
            if toggle_lock {
                let lock = !locked;
                self.key_status = match self.api.set_lock(lock, &ini_path()) {
                    Ok(()) if lock => "キーを暗号化してINIに保存しました (ロック中)".into(),
                    Ok(()) => "ロックを解除し、保存したキーを削除しました".into(),
                    Err(e) => e,
                };
            }
            ui.label(RichText::new("「ロック」でキーをWindowsのユーザーアカウントで暗号化して、実行ファイルと同じフォルダの settings.ini に保存し、次回起動時に自動で読み込みます。ロック中は入力欄がグレーアウトし、コピーもできません。「ロック解除」で保存したキーを削除します。未ロックのキーは保存されません (環境変数 ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY を初期値に使います)。OpenAI互換のローカルLLMは、GPTを選んでURLを変え、キーを空欄にします。").small().color(SUB));
        });
        self.show_api = show;

        let mut show = self.show_history;
        egui::Window::new("履歴").open(&mut show).show(&ctx, |ui| {
            if self.history.is_empty() {
                ui.label("履歴はありません");
            }
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    for (pos, neg) in self.history.clone() {
                        if ui
                            .button(pos.replace('\n', " ").chars().take(60).collect::<String>())
                            .clicked()
                        {
                            self.output = pos;
                            self.output_neg = neg;
                        }
                    }
                });
        });
        self.show_history = show;

        let mut show = self.show_saved;
        egui::Window::new("保存した設定")
            .open(&mut show)
            .show(&ctx, |ui| {
                if self.saved.is_empty() {
                    ui.label("保存された設定はありません");
                }
                for s in self.saved.clone() {
                    if ui.button(&s.name).clicked() {
                        self.restore(&s);
                    }
                }
            });
        self.show_saved = show;
    }
}

impl App {
    /// お気に入り登録ダイアログ (画面中央)。名前を付けて保存する
    fn fav_dialog_window(&mut self, ctx: &egui::Context) {
        let Some(mut name) = self.fav_dialog.take() else {
            return;
        };
        let mut keep = true;
        let mut save = false;
        let fresh = std::mem::take(&mut self.fav_dialog_fresh);
        egui::Window::new("お気に入りに追加")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("名前を付けて保存します (空欄なら自動で付けます)");
                let te = ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .desired_width(360.0)
                        .hint_text(format!("お気に入り {}", self.favorites.len() + 1)),
                );
                if fresh {
                    te.request_focus();
                }
                ui.label(
                    RichText::new(format!(
                        "ポジティブ: {}",
                        self.output.chars().take(70).collect::<String>()
                    ))
                    .small()
                    .color(SUB),
                );
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new("保存").fill(ACCENT)).clicked()
                        || (te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        save = true;
                    }
                    if ui.button("キャンセル").clicked() {
                        keep = false;
                    }
                });
            });
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            keep = false;
        }
        if save {
            self.api_status = match self
                .add_favorite(&name)
                .and_then(|()| self.save_new_favorite())
            {
                Ok(()) => format!("お気に入りに追加しました (Fav\\{})", self.favorites[0].file),
                Err(e) => e,
            };
        } else if keep {
            self.fav_dialog = Some(name);
        }
    }

    /// お気に入り一覧 (画面中央)。呼び出し・名前変更・コピー・削除ができる。範囲外クリック/Escで閉じる
    fn favorites_window(&mut self, ctx: &egui::Context) {
        if !self.show_favs {
            self.fav_shown = false;
            return;
        }
        let just_opened = !self.fav_shown;
        self.fav_shown = true;
        let mut open = true;
        let mut recall = None;
        let mut delete = None;
        let mut copy = None;
        let mut rename_done: Option<(usize, String)> = None;
        let (mut reload, mut open_folder) = (false, false);
        let shown = egui::Window::new("お気に入り")
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(640.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("検索");
                    ui.text_edit_singleline(&mut self.fav_filter);
                    ui.label(
                        RichText::new(format!("{}件", self.favorites.len()))
                            .small()
                            .color(SUB),
                    );
                    if ui
                        .button("再読み込み")
                        .on_hover_text("Favフォルダ内のMDファイルを読み直します")
                        .clicked()
                    {
                        reload = true;
                    }
                    if ui.button("Favフォルダを開く").clicked() {
                        open_folder = true;
                    }
                });
                ui.label(
                    RichText::new(format!("保存先: {}", fav_dir().display()))
                        .small()
                        .color(SUB),
                );
                if self.favorites.is_empty() {
                    ui.label(
                        RichText::new(
                            "お気に入りはありません。出力欄の「お気に入りに追加」で登録できます。",
                        )
                        .small()
                        .color(SUB),
                    );
                }
                let q = self.fav_filter.trim().to_lowercase();
                egui::ScrollArea::vertical()
                    .max_height(440.0)
                    .show(ui, |ui| {
                        for (i, f) in self.favorites.iter().enumerate() {
                            if !q.is_empty()
                                && !(f.name.to_lowercase().contains(&q)
                                    || f.positive.to_lowercase().contains(&q)
                                    || f.negative.to_lowercase().contains(&q))
                            {
                                continue;
                            }
                            egui::Frame::new()
                                .fill(INPUT)
                                .stroke(Stroke::new(1.0, BORDER))
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(egui::Margin::same(8))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        if let Some((ri, text)) =
                                            self.fav_rename.as_mut().filter(|(ri, _)| *ri == i)
                                        {
                                            let te = ui.add(
                                                egui::TextEdit::singleline(text)
                                                    .desired_width(280.0),
                                            );
                                            // Enterで確定したフレームは、再フォーカスしない (すると確定が打ち消される)
                                            let enter = te.lost_focus()
                                                && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                            if !enter {
                                                te.request_focus();
                                            }
                                            if ui.button("決定").clicked() || enter {
                                                rename_done = Some((*ri, text.clone()));
                                            }
                                        } else {
                                            ui.label(RichText::new(&f.name).strong());
                                        }
                                        ui.label(RichText::new(&f.model).small().color(SUB));
                                    });
                                    ui.label(
                                        RichText::new(
                                            f.positive
                                                .replace('\n', " ")
                                                .chars()
                                                .take(110)
                                                .collect::<String>(),
                                        )
                                        .small(),
                                    );
                                    if !f.negative.is_empty() {
                                        ui.label(
                                            RichText::new(format!(
                                                "ネガティブ: {}",
                                                f.negative
                                                    .replace('\n', " ")
                                                    .chars()
                                                    .take(80)
                                                    .collect::<String>()
                                            ))
                                            .small()
                                            .color(SUB),
                                        );
                                    }
                                    ui.horizontal(|ui| {
                                        if ui
                                            .add(egui::Button::new("呼び出す").fill(ACCENT))
                                            .clicked()
                                        {
                                            recall = Some(i);
                                        }
                                        if ui.button("名前変更").clicked() {
                                            self.fav_rename = Some((i, f.name.clone()));
                                        }
                                        if ui.button("コピー").clicked() {
                                            copy = Some(i);
                                        }
                                        // 削除は、もう一度押して確定する
                                        let confirm = self.fav_confirm_delete == Some(i);
                                        if ui
                                            .add(
                                                egui::Button::new(if confirm {
                                                    "本当に削除"
                                                } else {
                                                    "削除"
                                                })
                                                .fill(if confirm {
                                                    Color32::from_rgb(150, 50, 60)
                                                } else {
                                                    INPUT
                                                }),
                                            )
                                            .clicked()
                                        {
                                            if confirm {
                                                delete = Some(i);
                                            } else {
                                                self.fav_confirm_delete = Some(i);
                                            }
                                        }
                                    });
                                });
                            ui.add_space(4.0);
                        }
                    });
            });
        if let Some((i, name)) = rename_done {
            let name: String = name.trim().chars().take(60).collect();
            if let (Some(f), false) = (self.favorites.get_mut(i), name.is_empty()) {
                f.name = name;
                // MDファイルも新しい名前で作り直す (書けなければ元のファイルを更新するだけにする)
                let (dir, old) = (fav_dir(), f.file.clone());
                f.file.clear();
                match fav_write(&dir, f) {
                    Ok(()) => {
                        if f.file != old {
                            fav_delete(
                                &dir,
                                &Favorite {
                                    file: old,
                                    ..f.clone()
                                },
                            );
                        }
                    }
                    Err(e) => {
                        f.file = old;
                        let _ = fav_write(&dir, f);
                        self.api_status = format!("名前変更をファイルへ反映できませんでした: {e}");
                    }
                }
            }
            self.fav_rename = None;
        }
        if let Some(i) = copy {
            if let Some(f) = self.favorites.get(i) {
                ctx.copy_text(f.positive.clone());
            }
        }
        if let Some(i) = delete {
            if i < self.favorites.len() {
                let f = self.favorites.remove(i);
                fav_delete(&fav_dir(), &f);
            }
            self.fav_confirm_delete = None;
            self.fav_rename = None;
        }
        if let Some(i) = recall {
            self.recall_favorite(i);
            open = false;
        }
        if reload {
            self.fav_rename = None;
            self.fav_confirm_delete = None;
            self.reload_favorites();
        }
        if open_folder {
            let dir = fav_dir();
            let _ = std::fs::create_dir_all(&dir);
            #[cfg(windows)]
            let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
        }
        // 範囲外クリック・Escで閉じる
        if let Some(r) = shown {
            let outside = !just_opened
                && ctx.input(|i| i.pointer.any_click())
                && ctx
                    .pointer_interact_pos()
                    .is_some_and(|p| !r.response.rect.contains(p));
            if outside || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                open = false;
            }
        }
        if !open {
            self.show_favs = false;
            self.fav_shown = false;
            self.fav_rename = None;
            self.fav_confirm_delete = None;
        }
    }

    /// 辞書ピッカー: 検索して項目を押すと、対象フィールドへ英語プロンプトを追記する
    fn dict_window(&mut self, ctx: &egui::Context) {
        let Some((si, fi)) = self.dict_open else {
            self.dict_shown = None;
            return;
        };
        // 開いたフレーム(別の項目の辞書に切り替えたフレームも含む)は、外側クリックの判定をしない
        let just_opened = self.dict_shown != Some((si, fi));
        self.dict_shown = Some((si, fi));
        if just_opened {
            self.dict_sel = 0;
        }
        // ネガティブプロンプト欄の辞書 (si == NEG_PICKER) は、いまのネガティブの語を持つ仮の項目として開く
        let mut neg_field = (si == NEG_PICKER).then(|| negative_picker_field(&self.negatives));
        let field = match neg_field.as_mut() {
            Some(f) => f,
            None => &mut self.sections[si].fields[fi],
        };
        let mut open = true;
        let mut close = false;
        // アプリ画面の中央に表示する
        let shown = egui::Window::new(format!("辞書: {}", field.label))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(680.0)
            .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("辞書");
                let cur = match self.dict_sel {
                    0 => "この項目の辞書".to_string(),
                    1 => "全ての辞書".to_string(),
                    n => dict::all().get(n - 2).map_or(String::new(), |c| c.name.to_string()),
                };
                egui::ComboBox::from_id_salt("dict_sel").selected_text(cur).height(400.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.dict_sel, 0, "この項目の辞書");
                    ui.selectable_value(&mut self.dict_sel, 1, "全ての辞書");
                    ui.separator();
                    for (i, c) in dict::all().iter().enumerate() {
                        ui.selectable_value(&mut self.dict_sel, i + 2, c.name);
                    }
                });
                ui.label("検索 (日本語・英語)");
                ui.text_edit_singleline(&mut self.dict_filter);
            });
            ui.label(RichText::new("選んだ語は色付きの日本語チップとして入力欄に並び、プロンプトでは英語になります。もう一度押すと外せます。ホバーで英語を表示。").small().color(SUB));
            let q = self.dict_filter.trim().to_lowercase();
            egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                let shown_cats: Vec<&dict::Category> = match self.dict_sel {
                    0 => field.dicts.iter().filter_map(|id| dict::category(id)).collect(),
                    1 => dict::all().iter().collect(),
                    n => dict::all().get(n - 2).into_iter().collect(),
                };
                if self.dict_sel == 1 && q.is_empty() {
                    ui.label(RichText::new("検索語を入力すると、全ての辞書から該当する語を表示します。").small().color(SUB));
                }
                for c in shown_cats {
                    if self.dict_sel == 1 && q.is_empty() {
                        break;
                    }
                    let hit = |(en, ja): &&(&str, &str)| q.is_empty() || en.to_lowercase().contains(&q) || ja.to_lowercase().contains(&q);
                    if c.entries.iter().filter(hit).next().is_none() {
                        continue;
                    }
                    ui.label(RichText::new(c.name).strong().color(SUB));
                    // 種類を宣言していないカテゴリは、全体を1つの区切りとして扱う
                    let whole = [("", c.entries.len())];
                    let kinds = if c.kinds.is_empty() { &whole[..] } else { c.kinds };
                    let mut start = 0;
                    for (kind, n) in kinds {
                        let items: Vec<&(&str, &str)> = c.entries[start..start + n].iter().filter(hit).collect();
                        start += n;
                        if items.is_empty() {
                            continue;
                        }
                        if !kind.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{kind} ({})", items.len())).color(SUB));
                                if ui.small_button("すべて選ぶ").on_hover_text("この種類の語をまとめて選びます").clicked() {
                                    for (en, ja) in &items {
                                        if !field.has(en) {
                                            field.toggle(en, ja);
                                        }
                                    }
                                }
                                if ui.small_button("すべて外す").clicked() {
                                    field.state.tokens.retain(|t| !items.iter().any(|(en, _)| *en == t.en));
                                }
                            });
                        }
                        ui.horizontal_wrapped(|ui| {
                            for (en, ja) in &items {
                                // 同じ日本語訳が複数ある場合は英語を併記して区別する
                                let dup = items.iter().filter(|(_, j)| j == ja).count() > 1;
                                let label = if dup { format!("{ja} ({en})") } else { ja.to_string() };
                                let on = field.has(en);
                                let b = egui::Button::new(label).fill(if on { CHIP } else { INPUT });
                                if ui.add(b).on_hover_text(*en).clicked() {
                                    field.toggle(en, ja);
                                }
                            }
                        });
                        ui.add_space(4.0);
                    }
                    ui.add_space(6.0);
                }
            });
            if ui.button("閉じる").clicked() {
                close = true;
            }
        });
        // 辞書の範囲外をクリックしたら閉じる (Escでも閉じる)
        if let Some(r) = shown {
            let outside_click = !just_opened
                && ctx.input(|i| i.pointer.any_click())
                && ctx
                    .pointer_interact_pos()
                    .is_some_and(|p| !r.response.rect.contains(p));
            if outside_click || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                close = true;
            }
        }
        if let Some(f) = neg_field {
            self.negatives = f.state.tokens.iter().map(|t| t.en.clone()).collect();
        }
        if !open || close {
            self.dict_open = None;
            self.dict_shown = None;
        }
    }

    fn left_column(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("left_actions").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("コピー形式");
                egui::ComboBox::from_id_salt("copy_mode").selected_text(COPY_MODES[self.copy_mode]).show_ui(ui, |ui| {
                    for (i, name) in COPY_MODES.iter().enumerate() {
                        ui.selectable_value(&mut self.copy_mode, i, *name);
                    }
                });
                ui.label(RichText::new(["見出し・項目名は日本語、語は英語", "見出し・項目名・語をすべて英語", "英語の語だけをカンマ区切り (ネガティブは別の行)"][self.copy_mode]).small().color(SUB));
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 32.0) / 5.0;
                if ui.add(egui::Button::new("⟲ 設定をリセット").min_size(egui::vec2(w, 40.0))).clicked() {
                    self.reset();
                }
                if ui.add(egui::Button::new("🎲 全項目ランダム").min_size(egui::vec2(w, 40.0))).on_hover_text("全ての項目をランダムに設定します (空白になる項目もあります)").clicked() {
                    self.randomize_all();
                }
                if ui.add(egui::Button::new("💾 設定を保存").min_size(egui::vec2(w, 40.0))).clicked() {
                    let name = format!("設定 {}", self.saved.len() + 1);
                    self.saved.push(self.snapshot(name));
                }
                if ui.add(egui::Button::new("選択内容をコピー").min_size(egui::vec2(w, 40.0))).on_hover_text("選択・入力した内容を、上の「コピー形式」でクリップボードへコピーします").clicked() {
                    let text = self.copy_text();
                    if text.is_empty() {
                        self.api_status = "コピーできる選択内容がありません".into();
                    } else {
                        ui.ctx().copy_text(text);
                        self.api_status = "選択内容をクリップボードにコピーしました".into();
                    }
                }
                if ui.add(egui::Button::new(RichText::new("プロンプトを生成").strong()).fill(ACCENT).min_size(egui::vec2(w, 40.0))).clicked() {
                    self.generate(&ui.ctx().clone());
                }
            });
            ui.add_space(4.0);
        });

        let target = self.scroll_to.take();
        let restore = std::mem::take(&mut self.scroll_restore[0]);
        let mut left = egui::ScrollArea::vertical().id_salt("left_scroll").auto_shrink([false, false]);
        if restore {
            left = left.vertical_scroll_offset(self.scroll[0]);
        }
        let left_out = left.show(ui, |ui| {
            for (pos, item) in LAYOUT.into_iter().enumerate() {
                let mut folded = self.folded[pos];
                let Some(si) = item else {
                    if target == Some(usize::MAX) {
                        folded = false;
                        ui.scroll_to_cursor(Some(Align::TOP));
                    }
                card(ui, |ui| {
                    if heading_random(ui, "キャラクター設定", false, "キャラクターの外見を言語指定します。各項目はランダム選択も可能です。", &mut folded) {
                        self.gender = self.rng.opt(3);
                        self.age = self.rng.opt(5);
                        self.count = self.rng.opt(2);
                        self.appearance = random_appearance(&mut self.rng);
                    }
                    if folded {
                        return;
                    }
                    egui::CollapsingHeader::new(RichText::new("基本").strong()).id_salt("char_basic").default_open(true).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_sized([40.0, 22.0], egui::Label::new("人数"));
                        chips(ui, &COUNTS, &mut self.count);
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if random_btn(ui) {
                                self.count = self.rng.opt(2);
                            }
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.add_sized([40.0, 22.0], egui::Label::new("性別"));
                        chips(ui, &GENDERS, &mut self.gender);
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if random_btn(ui) {
                                self.gender = self.rng.opt(3);
                            }
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.add_sized([40.0, 22.0], egui::Label::new("年齢"));
                        chips(ui, &AGES, &mut self.age);
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if random_btn(ui) {
                                self.age = self.rng.opt(5);
                            }
                        });
                    });
                    });
                    egui::CollapsingHeader::new(RichText::new("外見").strong()).id_salt("char_look").default_open(true).show(ui, |ui| {
                    ui.label(RichText::new("外見の特徴 (自由記述)").small());
                    ui.horizontal(|ui| {
                        let w = ui.available_width() - 84.0;
                        ui.add_sized(
                            [w, 48.0],
                            egui::TextEdit::multiline(&mut self.appearance)
                                .hint_text("例：身長、体型、肌の色、髪の色、髪型、目の形、鼻、口、眉、雰囲気など\n複数ある場合はカンマ区切りで入力してください。"),
                        );
                        if random_btn(ui) {
                            self.appearance = random_appearance(&mut self.rng);
                        }
                    });
                    });
                });
                    self.folded[pos] = folded;
                    continue;
                };
                if target == Some(si) {
                    folded = false;
                    ui.scroll_to_cursor(Some(Align::TOP));
                }
                let sec = &mut self.sections[si];
                let rng = &mut self.rng;
                let dict_open = &mut self.dict_open;
                let simple_mode = self.simple_mode;
                card(ui, |ui| {
                    if heading_random(ui, sec.title, true, sec.sub, &mut folded) {
                        for fl in sec.fields.iter_mut().filter(|fl| !simple_mode || fl.simple) {
                            fl.randomize(rng);
                        }
                    }
                    if folded {
                        return;
                    }
                    // 行の幅配分: [項目名][入力欄 = 残り全部][ランダム][辞書]。ボタンがペインの右端に揃う
                    let sp = ui.spacing().item_spacing.x;
                    let field_w = (ui.available_width() - ui.spacing().indent - LABEL_W - RANDOM_BTN_W - DICT_BTN_W - 3.0 * sp).max(160.0);
                    let mut start = 0;
                    for (gi, (gname, n)) in sec.groups.iter().enumerate() {
                        let range = start..start + n;
                        start += n;
                        if simple_mode && !range.clone().any(|fi| sec.fields[fi].simple) {
                            continue;
                        }
                        egui::CollapsingHeader::new(RichText::new(*gname).strong()).id_salt((si, gi)).default_open(true).show(ui, |ui| {
                            for fi in range {
                                if simple_mode && !sec.fields[fi].simple {
                                    continue;
                                }
                                    let fl = &mut sec.fields[fi];
                                ui.horizontal(|ui| {
                                    // 項目名は固定幅の領域に左揃えで置く (名前の長さで入力欄の左端がずれないように)
                                    let (rect, _) = ui.allocate_exact_size(egui::vec2(LABEL_W, 22.0), egui::Sense::hover());
                                    ui.painter().text(rect.left_center(), egui::Align2::LEFT_CENTER, fl.label, egui::TextStyle::Body.resolve(ui.style()), ui.visuals().text_color());
                                    field_input(ui, fl, field_w);
                                    if ui.add_sized([RANDOM_BTN_W, 22.0], egui::Button::new(RichText::new("⟳ ランダム").small())).clicked() {
                                        fl.randomize(rng);
                                    }
                                    // 辞書の無い項目も列を空けて、「ランダム」の位置を揃える
                                    if fl.dicts.is_empty() {
                                        ui.add_space(DICT_BTN_W);
                                    } else if ui.add_sized([DICT_BTN_W, 22.0], egui::Button::new(RichText::new("辞書").small())).clicked() {
                                        *dict_open = Some((si, fi));
                                    }
                                });
                            }
                        });
                    }
                });
                self.folded[pos] = folded;
            }
            card(ui, |ui| {
                heading(ui, "その他 (自由記述)", false, "上の項目に当てはまらない内容を自由に書けます。複数ある場合はカンマ区切りで入力してください。");
                ui.add_sized(
                    [ui.available_width(), 60.0],
                    egui::TextEdit::multiline(&mut self.other).hint_text("例：背景に桜吹雪、手に小さな猫を抱いている、夕焼けの空 など"),
                );
            });
        });
        self.scroll[0] = left_out.state.clamped_offset().y;
    }

    fn right_column(&mut self, ui: &mut egui::Ui) {
        // 下部の操作部は左ペインと同様に固定し、上のカード群だけをスクロールさせる
        egui::Panel::bottom("right_actions").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 8.0) / 2.0;
                if ui
                    .add(egui::Button::new("⧉ コピー").min_size(egui::vec2(w, 40.0)))
                    .clicked()
                {
                    ui.ctx().copy_text(self.output.clone());
                }
                if ui
                    .add(
                        egui::Button::new(RichText::new("調整する").strong())
                            .fill(ACCENT)
                            .min_size(egui::vec2(w, 40.0)),
                    )
                    .clicked()
                {
                    self.adjust(&ui.ctx().clone());
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.api.enabled, "LLM APIでプロンプト生成・修正");
                ui.checkbox(&mut self.quality_tags, "品質タグを付ける");
                ui.checkbox(
                    &mut self.mj_no_params,
                    "Midjourney: パラメータ情報を付けない",
                );
            });
            if !self.api_status.is_empty() {
                ui.label(RichText::new(&self.api_status).small().color(SUB));
            }
            ui.add_space(4.0);
        });

        let restore = std::mem::take(&mut self.scroll_restore[1]);
        let mut right = egui::ScrollArea::vertical().id_salt("right_scroll").auto_shrink([false, false]);
        if restore {
            right = right.vertical_scroll_offset(self.scroll[1]);
        }
        let right_out = right.show(ui, |ui| {
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(">_ プロンプト編集・CLI").strong().size(15.0));
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        egui::ComboBox::from_id_salt("model").selected_text(FORMATS[self.model].name).show_ui(ui, |ui| {
                            for (i, m) in FORMATS.iter().enumerate() {
                                ui.selectable_value(&mut self.model, i, m.name);
                            }
                        });
                        ui.label(RichText::new("モデル").small().color(SUB));
                    });
                });
                ui.label(RichText::new("上記の設定をもとに、プロンプトを生成・調整できます。").small().color(SUB));
                ui.add_space(4.0);
                ui.label(RichText::new("ポジティブ").strong());
                ui.add_sized(
                    [ui.available_width(), 150.0],
                    egui::TextEdit::multiline(&mut self.output)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("プロンプトが生成されます\n「プロンプトを生成」ボタンを押してください。"),
                );
                ui.horizontal(|ui| {
                    if ui.button("⧉ コピー").clicked() {
                        ui.ctx().copy_text(self.output.clone());
                    }
                    if ui.button("★ お気に入りに追加").on_hover_text("今のポジティブ/ネガティブに名前を付けて登録します").clicked() {
                        if self.output.trim().is_empty() && self.output_neg.trim().is_empty() {
                            self.api_status = "登録できるプロンプトがありません".into();
                        } else {
                            self.fav_dialog = Some(String::new());
                            self.fav_dialog_fresh = true;
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(format!("文字数 : {}", self.output.chars().count())).small());
                    });
                });
                ui.add_space(4.0);
                ui.label(RichText::new("ネガティブ").strong());
                ui.add_sized(
                    [ui.available_width(), 80.0],
                    egui::TextEdit::multiline(&mut self.output_neg)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("ネガティブプロンプト (Midjourney以外は常に出力。Midjourneyは入力したときだけ)"),
                );
                ui.horizontal(|ui| {
                    if ui.button("⧉ コピー").clicked() {
                        ui.ctx().copy_text(self.output_neg.clone());
                    }
                    if ui.button("🗑 全てクリア").clicked() {
                        self.output.clear();
                        self.output_neg.clear();
                        self.output_note.clear();
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(format!("文字数 : {}", self.output_neg.chars().count())).small());
                    });
                });
                if !self.output_note.is_empty() {
                    ui.label(RichText::new(&self.output_note).small().color(SUB));
                }
            });

            card(ui, |ui| {
                heading(ui, "プロンプトの調整", false, "追加・修正したい内容を入力して、下の「調整する」を押します。");
                ui.add_sized([ui.available_width(), 70.0], egui::TextEdit::multiline(&mut self.adjust).hint_text("例：髪を銀髪に変更、背景に桜を追加 (APIが有効なら、ポジティブ・ネガティブと一緒にAIへ依頼して書き換え、無効なら末尾に追加します)"));
            });

            card(ui, |ui| {
                heading(ui, "ネガティブプロンプト (任意)", false, "生成したくない要素を指定できます。");
                ui.add_sized(
                    [ui.available_width(), 60.0],
                    egui::TextEdit::multiline(&mut self.negative_input).hint_text("例：ぼやけた、低品質、文字、ロゴ、余分な指、変形、異常な体 など"),
                );
                ui.with_layout(egui::Layout::right_to_left(Align::Min), |ui| {
                    if ui.button("追加").clicked() && !self.negative_input.trim().is_empty() {
                        let words = self.translate_free(&self.negative_input);
                        self.negatives = merge_unique(self.negatives.iter().cloned().chain(words));
                        self.negative_input.clear();
                    }
                    if ui.button("辞書").on_hover_text("ネガティブにした方がよい語を、種類ごとにまとめて選べます").clicked() {
                        self.dict_open = Some((NEG_PICKER, 0));
                    }
                    let preset = FORMATS[self.model].neg;
                    if !preset.is_empty()
                        && ui
                            .button("モデル標準")
                            .on_hover_text(format!("{} 向けの標準ネガティブを追加します: {preset}", FORMATS[self.model].name))
                            .clicked()
                    {
                        let add = preset.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                        self.negatives = merge_unique(self.negatives.iter().cloned().chain(add));
                    }
                });
                let mut remove = None;
                ui.horizontal_wrapped(|ui| {
                    for (i, n) in self.negatives.iter().enumerate() {
                        // 辞書にある語は日本語も併記する (出力は英語のまま)
                        let ja = dict::category("negative_prompt")
                            .and_then(|c| c.entries.iter().find(|(en, _)| en.eq_ignore_ascii_case(n)))
                            .map(|(_, ja)| *ja);
                        let label = match ja {
                            Some(ja) => format!("{ja} ({n})  ✕"),
                            None => format!("{n}  ✕"),
                        };
                        if ui.small_button(label).clicked() {
                            remove = Some(i);
                        }
                    }
                });
                if let Some(i) = remove {
                    self.negatives.remove(i);
                }
            });

            card(ui, |ui| {
                heading(ui, "生成パラメータ (任意)", false, "出力の調整ができます。");
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("preset_param").selected_text("既定の設定を使用").show_ui(ui, |ui| {
                        if ui.selectable_label(false, "既定の設定を使用").clicked() {
                            (self.quality, self.chaos, self.stylize) = (1.0, 0.0, 100.0);
                        }
                        if ui.selectable_label(false, "高品質").clicked() {
                            (self.quality, self.chaos, self.stylize) = (2.0, 0.0, 250.0);
                        }
                        if ui.selectable_label(false, "創造的").clicked() {
                            (self.quality, self.chaos, self.stylize) = (1.0, 50.0, 600.0);
                        }
                    });
                    ui.label(RichText::new("スタイル").small().color(SUB));
                    egui::ComboBox::from_id_salt("style").selected_text(STYLES[self.style]).width(80.0).show_ui(ui, |ui| {
                        for (i, s) in STYLES.iter().enumerate() {
                            ui.selectable_value(&mut self.style, i, *s);
                        }
                    });
                    ui.label(RichText::new("アスペクト比").small().color(SUB));
                    egui::ComboBox::from_id_salt("aspect").selected_text(ASPECTS[self.aspect]).width(60.0).show_ui(ui, |ui| {
                        for (i, s) in ASPECTS.iter().enumerate() {
                            ui.selectable_value(&mut self.aspect, i, *s);
                        }
                    });
                });
                egui::Grid::new("params").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("品質 (quality)");
                        ui.add(egui::Slider::new(&mut self.quality, 0.25..=2.0).step_by(0.25));
                    });
                    ui.horizontal(|ui| {
                        ui.label("chaos");
                        ui.add(egui::Slider::new(&mut self.chaos, 0.0..=100.0).integer());
                    });
                    ui.end_row();
                    ui.label("");
                    ui.horizontal(|ui| {
                        ui.label("stylize");
                        ui.add(egui::Slider::new(&mut self.stylize, 0.0..=1000.0).integer());
                    });
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.use_seed, "シード値を指定する");
                    ui.add(egui::TextEdit::singleline(&mut self.seed).hint_text("例：12345").desired_width(140.0));
                    if random_btn(ui) {
                        self.seed = (self.rng.next() % 4_294_967_295).to_string();
                    }
                });
            });

        });
        self.scroll[1] = right_out.state.clamped_offset().y;
    }
}

/// 保存した起動位置・サイズ。画面外(モニター構成の変更など)や不正な値なら使わない
fn saved_window() -> Option<[f32; 4]> {
    migrate_legacy_files();
    let map = ini_read(&ini_path());
    let from_ini = ["window.x", "window.y", "window.width", "window.height"]
        .iter()
        .map(|k| map.get(*k).and_then(|v| v.parse::<f32>().ok()))
        .collect::<Option<Vec<f32>>>();
    // 旧バージョンは位置を state.json に保存していた
    let legacy = || {
        let text = read_text_limited(&state_path(), 50 << 20)?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        Some(
            v["window"]
                .as_array()?
                .iter()
                .filter_map(|x| x.as_f64())
                .map(|x| x as f32)
                .collect::<Vec<f32>>(),
        )
    };
    let w = from_ini.or_else(legacy)?;
    let [x, y, width, height] = <[f32; 4]>::try_from(w).ok()?;
    window_is_usable(x, y, width, height).then_some([x, y, width, height])
}

fn window_is_usable(x: f32, y: f32, w: f32, h: f32) -> bool {
    if !(w.is_finite() && h.is_finite() && x.is_finite() && y.is_finite())
        || !(600.0..=10000.0).contains(&w)
        || !(400.0..=8000.0).contains(&h)
    {
        return false;
    }
    // タイトルバーの一部が、いずれかのモニター(仮想スクリーン)の中に見えていること
    #[cfg(windows)]
    {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetSystemMetrics(index: i32) -> i32;
        }
        // SAFETY: 引数を取るだけの読み取りAPI
        let (vx, vy, vw, vh) = unsafe {
            (
                GetSystemMetrics(76),
                GetSystemMetrics(77),
                GetSystemMetrics(78),
                GetSystemMetrics(79),
            )
        };
        if vw > 0 && vh > 0 {
            let (px, py) = (x + 80.0, y + 12.0);
            return px >= vx as f32
                && px < (vx + vw) as f32
                && py >= vy as f32
                && py < (vy + vh) as f32;
        }
    }
    true
}

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1400.0, 1000.0])
        .with_title("Prompt Generator");
    if let Some([x, y, w, h]) = saved_window() {
        viewport = viewport.with_position([x, y]).with_inner_size([w, h]);
    }
    // 描画はOpenGL(glow)を優先する: wgpuより初期化が速く、メモリも少ない。
    // OpenGLが使えない環境(古いGPU・リモート接続など)では、wgpuに切り替えて再試行する
    let run = |renderer: eframe::Renderer, viewport: egui::ViewportBuilder| {
        let options = eframe::NativeOptions {
            viewport,
            renderer,
            ..Default::default()
        };
        eframe::run_native(
            "Prompt Generator",
            options,
            Box::new(|cc| Ok(Box::new(App::new(cc)))),
        )
    };
    match run(eframe::Renderer::Glow, viewport.clone()) {
        Ok(()) => Ok(()),
        Err(_) => run(eframe::Renderer::Wgpu, viewport),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_prompt_keeps_only_the_prompt() {
        assert_eq!(
            clean_prompt("```\nPrompt: \"blunt bangs, blue eyes\"\n```"),
            "blunt bangs, blue eyes"
        );
        assert_eq!(
            clean_prompt("  long hair,\nsmiling.  "),
            "long hair, smiling"
        );
    }

    #[test]
    fn parse_pos_neg_routes_positive_and_negative() {
        // JSON (コードブロック・前置き付き)
        let raw = "Here you go:\n```json\n{\"positive\": \"1girl, long hair\", \"negative\": \"blurry, bad hands\"}\n```";
        assert_eq!(
            parse_pos_neg(raw),
            Ok((
                "1girl, long hair".to_string(),
                "blurry, bad hands".to_string()
            ))
        );
        // ラベル形式
        assert_eq!(
            parse_pos_neg("1girl, long hair\nNegative prompt: blurry"),
            Ok(("1girl, long hair".to_string(), "blurry".to_string()))
        );
        // ネガティブ無し
        assert_eq!(
            parse_pos_neg("{\"positive\":\"a\",\"negative\":\"\"}"),
            Ok(("a".to_string(), String::new()))
        );
        // 日本語が残っていればエラー / 空もエラー
        assert!(parse_pos_neg("{\"positive\":\"ぱっつん前髪\",\"negative\":\"\"}").is_err());
        assert!(parse_pos_neg("{\"positive\":\"\",\"negative\":\"\"}").is_err());
    }

    #[test]
    fn split_free_handles_all_delimiters() {
        assert_eq!(
            split_free("a b　c,d，e、f;g\nh"),
            vec!["a", "b", "c", "d", "e", "f", "g", "h"]
        );
    }

    /// 模擬サーバーを1回だけ応答させ、受け取ったリクエスト全文を返す
    fn mock_server(reply: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        mock_server_status("200 OK", reply)
    }

    fn mock_server_status(
        status: &'static str,
        reply: &'static str,
    ) -> (u16, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // ヘッダーと Content-Length 分の本文を読み切る
            let mut data = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap();
                data.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&data).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len = text[..i]
                        .to_lowercase()
                        .split("content-length:")
                        .nth(1)
                        .and_then(|r| r.split("\r\n").next())
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if data.len() >= i + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&data).to_string();
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.len(),
                reply
            );
            s.write_all(resp.as_bytes()).unwrap();
            req
        });
        (port, h)
    }

    fn api_for(p: Provider, port: u16, base: &str) -> ApiSettings {
        let mut api = ApiSettings::default();
        api.provider = p;
        let c = api.cur_mut();
        c.base_url = format!("http://127.0.0.1:{port}{base}");
        c.model = "m".into();
        c.key = "k".into();
        api
    }

    #[test]
    fn gpt_openai_compatible() {
        let (port, srv) = mock_server(
            r#"{"choices":[{"message":{"content":"{\"positive\":\"blunt bangs, blue eyes\",\"negative\":\"blurry\"}"}}]}"#,
        );
        let f = FORMATS.iter().find(|f| f.name == "Illustrious").unwrap();
        let r = llm_generate(
            &api_for(Provider::Gpt, port, "/v1"),
            f,
            "ぱっつん前髪, blue eyes",
            "ぼやけた",
        );
        let req = srv.join().unwrap();
        assert!(req.starts_with("POST /v1/chat/completions"), "{req}");
        assert!(req.to_lowercase().contains("authorization: bearer k"));
        // 対象モデル名・形式ルール・入力(選択内容とネガティブ)がAIに渡る
        assert!(
            req.contains("Illustrious") && req.contains("Danbooru-style tags"),
            "{req}"
        );
        assert!(
            req.contains("ぱっつん前髪") && req.contains("ぼやけた"),
            "{req}"
        );
        assert_eq!(
            r,
            Ok(("blunt bangs, blue eyes".to_string(), "blurry".to_string()))
        );
    }

    #[test]
    fn claude_messages_api() {
        let (port, srv) = mock_server(
            r#"{"content":[{"type":"text","text":"{\"positive\":\"blunt bangs, blue eyes\",\"negative\":\"blurry\"}"}]}"#,
        );
        let f = FORMATS.iter().find(|f| f.name == "Midjourney").unwrap();
        let r = llm_generate(
            &api_for(Provider::Claude, port, "/v1"),
            f,
            "ぱっつん前髪, blue eyes",
            "",
        );
        let req = srv.join().unwrap();
        assert!(req.starts_with("POST /v1/messages"), "{req}");
        let low = req.to_lowercase();
        assert!(
            low.contains("x-api-key: k") && low.contains("anthropic-version: 2023-06-01"),
            "{req}"
        );
        assert!(
            req.contains("\"system\"") && req.contains("Midjourney"),
            "{req}"
        );
        assert_eq!(
            r,
            Ok(("blunt bangs, blue eyes".to_string(), "blurry".to_string()))
        );
    }

    #[test]
    fn gemini_generate_content() {
        let (port, srv) = mock_server(
            r#"{"candidates":[{"content":{"parts":[{"text":"{\"positive\":\"blunt bangs, blue eyes\",\"negative\":\"blurry\"}"}]}}]}"#,
        );
        let f = FORMATS.iter().find(|f| f.name == "Pony").unwrap();
        let r = llm_generate(
            &api_for(Provider::Gemini, port, "/v1beta"),
            f,
            "ぱっつん前髪, blue eyes",
            "",
        );
        let req = srv.join().unwrap();
        assert!(
            req.starts_with("POST /v1beta/models/m:generateContent"),
            "{req}"
        );
        assert!(req.to_lowercase().contains("x-goog-api-key: k"), "{req}");
        assert!(
            req.contains("systemInstruction") && req.contains("Pony"),
            "{req}"
        );
        assert_eq!(
            r,
            Ok(("blunt bangs, blue eyes".to_string(), "blurry".to_string()))
        );
    }

    #[test]
    fn japanese_in_reply_is_rejected() {
        let (port, srv) = mock_server(
            r#"{"content":[{"type":"text","text":"{\"positive\":\"ぱっつん前髪\",\"negative\":\"\"}"}]}"#,
        );
        let r = llm_generate(
            &api_for(Provider::Claude, port, "/v1"),
            &FORMATS[0],
            "x",
            "",
        );
        srv.join().unwrap();
        assert!(r.is_err());
    }
    /// 出力形式ごとの組み立て (品質タグ・ネガティブ・サイズ・snake_case の空白化・ポジ/ネガ分割) を確認する
    #[test]
    fn output_formats() {
        let mut app = App::blank();
        app.model = FORMATS.iter().position(|f| f.name == "Pony").unwrap();
        app.finish("1girl, looking_at_viewer".into(), "bad hands".into());
        assert_eq!(
            app.output,
            "score_9, score_8_up, score_7_up, score_6_up, source_anime, 1girl, looking at viewer"
        );
        assert_eq!(
            app.output_neg,
            "score_6, score_5, score_4, text, watermark, signature, bad hands"
        );
        assert_eq!(app.output_note, "推奨サイズ 896x1152 (3:4)");

        // ユーザー入力が無くても、Midjourney以外はネガティブが出る
        app.model = FORMATS
            .iter()
            .position(|f| f.name == "Illustrious")
            .unwrap();
        app.finish("1girl".into(), String::new());
        assert_eq!(
            app.output_neg,
            "worst quality, low quality, bad quality, bad anatomy"
        );
        // 品質タグを外すと既定のネガティブも付かない
        app.quality_tags = false;
        app.finish("1girl".into(), String::new());
        assert_eq!(app.output, "1girl");
        assert_eq!(app.output_neg, "");
    }

    #[test]
    fn midjourney_params_and_negative() {
        let mut app = App::blank();
        app.model = 0;
        // 既定: パラメータ無し・ネガティブ無し
        assert!(app.mj_no_params);
        app.finish("a b".into(), String::new());
        assert_eq!(app.output, "a b");
        assert_eq!(app.output_neg, "");
        // 明示的にネガティブを入力したときだけ、ネガティブが出る
        app.finish("a b".into(), "blur".into());
        assert_eq!(app.output, "a b");
        assert_eq!(app.output_neg, "blur");
        // パラメータ有りに切り替えると /imagine とパラメータが付く
        app.mj_no_params = false;
        app.finish("a b".into(), "blur".into());
        assert!(
            app.output.starts_with("/imagine prompt:\na b\n--ar 3:4")
                && app.output.contains("--no blur"),
            "{}",
            app.output
        );
    }

    #[test]
    fn llm_hint_is_sent_for_tag_models() {
        let (port, srv) = mock_server(
            r#"{"content":[{"type":"text","text":"{\"positive\":\"1girl, long hair\",\"negative\":\"\"}"}]}"#,
        );
        let f = FORMATS.iter().find(|f| f.name == "NoobAI").unwrap();
        let r = llm_generate(
            &api_for(Provider::Claude, port, "/v1"),
            f,
            "長い髪の女性",
            "",
        );
        let req = srv.join().unwrap();
        assert!(
            req.contains("NoobAI") && req.contains("Danbooru-style tags"),
            "{req}"
        );
        assert_eq!(r, Ok(("1girl, long hair".to_string(), String::new())));
    }
    #[test]
    fn fetch_models_claude() {
        let (port, srv) =
            mock_server(r#"{"data":[{"id":"claude-haiku-5-5"},{"id":"claude-sonnet-5-5"}]}"#);
        let r = fetch_models(&api_for(Provider::Claude, port, "/v1"));
        let req = srv.join().unwrap();
        assert!(req.starts_with("GET /v1/models"), "{req}");
        assert!(req.to_lowercase().contains("x-api-key: k"));
        assert_eq!(
            r,
            Ok(vec![
                "claude-haiku-5-5".to_string(),
                "claude-sonnet-5-5".to_string()
            ])
        );
    }

    #[test]
    fn fetch_models_gpt_filters_non_chat() {
        let (port, srv) = mock_server(
            r#"{"data":[{"id":"gpt-4o"},{"id":"text-embedding-3-small"},{"id":"whisper-1"},{"id":"gpt-4o-mini"}]}"#,
        );
        let r = fetch_models(&api_for(Provider::Gpt, port, "/v1"));
        let req = srv.join().unwrap();
        assert!(req.starts_with("GET /v1/models"), "{req}");
        assert!(req.to_lowercase().contains("authorization: bearer k"));
        assert_eq!(r, Ok(vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string()]));
    }

    #[test]
    fn fetch_models_gemini_only_generate_content() {
        let (port, srv) = mock_server(
            r#"{"models":[{"name":"models/gemini-2.5-flash","supportedGenerationMethods":["generateContent"]},{"name":"models/embedding-001","supportedGenerationMethods":["embedContent"]}]}"#,
        );
        let r = fetch_models(&api_for(Provider::Gemini, port, "/v1beta"));
        let req = srv.join().unwrap();
        assert!(req.starts_with("GET /v1beta/models"), "{req}");
        assert!(req.to_lowercase().contains("x-goog-api-key: k"));
        assert_eq!(r, Ok(vec!["gemini-2.5-flash".to_string()]));
    }
    #[test]
    fn http_error_shows_server_message() {
        let (port, srv) = mock_server_status(
            "400 Bad Request",
            r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key."}}"#,
        );
        let r = fetch_models(&api_for(Provider::Gemini, port, "/v1beta"));
        srv.join().unwrap();
        let e = r.unwrap_err();
        assert!(
            e.contains("HTTP 400") && e.contains("API key not valid"),
            "{e}"
        );
    }

    #[test]
    fn missing_key_is_reported_before_request() {
        let mut api = ApiSettings::default();
        api.provider = Provider::Gemini;
        api.cur_mut().key = "  ".into();
        assert!(fetch_models(&api).unwrap_err().contains("APIキーが未設定"));
        assert!(
            llm_generate(&api, &FORMATS[0], "x", "")
                .unwrap_err()
                .contains("APIキーが未設定")
        );
    }

    #[test]
    fn adjust_sends_positive_negative_and_instruction() {
        let (port, srv) = mock_server(
            r#"{"content":[{"type":"text","text":"{\"positive\":\"1girl, silver hair\",\"negative\":\"blurry, text\"}"}]}"#,
        );
        let f = FORMATS.iter().find(|f| f.name == "Illustrious").unwrap();
        let r = llm_adjust(
            &api_for(Provider::Claude, port, "/v1"),
            f,
            "1girl, black hair",
            "blurry",
            "髪を銀髪に、文字は出さない",
        );
        let req = srv.join().unwrap();
        // 現在のポジティブ・ネガティブ・修正内容の3つがAIに渡る
        assert!(
            req.contains("1girl, black hair")
                && req.contains("blurry")
                && req.contains("髪を銀髪に"),
            "{req}"
        );
        assert!(req.contains("Illustrious"), "{req}");
        assert_eq!(
            r,
            Ok(("1girl, silver hair".to_string(), "blurry, text".to_string()))
        );
    }

    #[test]
    fn local_adjust_appends_when_api_disabled() {
        let mut app = App::blank();
        app.output = "1girl, long hair".into();
        app.adjust = "背景に桜".into();
        app.adjust(&egui::Context::default());
        assert_eq!(app.output, "1girl, long hair, 背景に桜");
        assert!(app.adjust.is_empty());
    }
    #[test]
    fn state_roundtrip() {
        let mut a = App::blank();
        a.gender = Some(1);
        a.appearance = "黒髪".into();
        a.sections[0].fields[0].state = FieldState {
            tokens: vec![Tok {
                ja: "卵型の顔".into(),
                en: "oval face".into(),
            }],
            free: "しゅっとした 輪郭".into(),
        };
        a.negatives = vec!["blur".into()];
        a.output = "1girl".into();
        a.history = vec![("p".into(), "n".into())];
        a.api.cur_mut().key = "secret".into();
        a.saved.push(a.snapshot("設定 1".into()));
        let json = a.to_json();
        assert!(!json.to_string().contains("secret"), "APIキーは保存しない");

        let mut b = App::blank();
        b.load_json(&json);
        assert_eq!(b.gender, Some(1));
        assert_eq!(b.appearance, "黒髪");
        let mut o = App::blank();
        o.other = "桜吹雪, 小さな猫".into();
        assert!(o.collect().0.ends_with("桜吹雪, 小さな猫"));
        assert!(o.context_text().contains("## その他
- 桜吹雪, 小さな猫"));
        let mut o2 = App::blank();
        o2.load_json(&o.to_json());
        assert_eq!(o2.other, "桜吹雪, 小さな猫");
        assert_eq!(b.sections[0].fields[0].state.tokens[0].en, "oval face");
        assert_eq!(b.sections[0].fields[0].state.free, "しゅっとした 輪郭");
        assert_eq!(b.negatives, vec!["blur".to_string()]);
        assert_eq!(b.output, "1girl");
        assert_eq!(b.history, vec![("p".to_string(), "n".to_string())]);
        assert_eq!(b.saved.len(), 1);
        assert_eq!(b.saved[0].values[0][0].free, "しゅっとした 輪郭");
    }

    #[test]
    fn category_random_fills_or_blanks_every_field() {
        let mut app = App::blank();
        let mut rng = Rng::new();
        let (mut filled, mut empty) = (0, 0);
        for _ in 0..200 {
            for fl in app.sections[0].fields.iter_mut() {
                fl.randomize(&mut rng);
                // 語が入るか空白になるか。入る場合は必ず1語
                assert!(fl.state.tokens.len() <= 1 && fl.state.free.is_empty());
                if fl.state.tokens.is_empty() { empty += 1 } else { filled += 1 }
            }
        }
        assert!(filled > 0 && empty > 0, "{filled} {empty}");
    }

    #[test]
    fn dpapi_roundtrip_and_ciphertext_differs() {
        let enc = dpapi::protect(b"sk-secret-key").unwrap();
        assert!(!String::from_utf8_lossy(&enc).contains("sk-secret-key"));
        assert_eq!(dpapi::unprotect(&enc).unwrap(), b"sk-secret-key");
        assert_eq!(hex_decode(&hex_encode(&enc)).unwrap(), enc);
    }

    #[test]
    fn ini_roundtrip() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("api.claude_key".to_string(), "abcd".to_string());
        map.insert("window.x".to_string(), "10".to_string());
        let text = ini_render(&map);
        assert!(
            text.contains("[api]") && text.contains("claude_key=abcd") && text.contains("[window]"),
            "{text}"
        );
        assert_eq!(ini_parse(&text), map);
    }

    #[test]
    fn lock_encrypts_to_ini_reload_and_unlock_deletes() {
        let dir = std::env::temp_dir().join(format!("pg_test_{}", std::process::id()));
        let path = dir.join("settings.ini");
        let _ = std::fs::remove_dir_all(&dir);

        let mut api = ApiSettings::default();
        api.provider = Provider::Claude;
        api.cur_mut().key = "sk-ant-TEST".into();
        api.set_lock(true, &path).unwrap();
        assert!(api.cur().locked);
        let ini = std::fs::read_to_string(&path).unwrap();
        assert!(
            ini.contains("claude_key=") && !ini.contains("sk-ant-TEST"),
            "平文で保存されていない: {ini}"
        );

        // 再起動相当: 新しい設定に、INIからキーを読み込む
        let mut api2 = ApiSettings::default();
        api2.cfg[0].key.clear();
        api2.load_locked_keys(&path);
        assert_eq!(api2.cfg[0].key, "sk-ant-TEST");
        assert!(api2.cfg[0].locked);
        assert!(!api2.cfg[1].locked && !api2.cfg[2].locked);

        // 解除: INIから削除され、キーも消える
        api.set_lock(false, &path).unwrap();
        assert!(!api.cur().locked && api.cur().key.is_empty());
        assert!(!path.exists(), "保存したキーが残っている");

        // 空のキーはロックできない
        assert!(api.set_lock(true, &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// 生成ボタン: AIの応答のポジティブ/ネガティブが、それぞれの欄に振り分けられる (品質タグ・既定ネガティブも付く)
    #[test]
    fn generate_routes_ai_result_to_positive_and_negative() {
        let (port, srv) = mock_server(
            r#"{"choices":[{"message":{"content":"{\"positive\":\"1girl, blunt bangs\",\"negative\":\"blurry\"}"}}]}"#,
        );
        let mut app = App::blank();
        app.api = api_for(Provider::Gpt, port, "/v1");
        app.api.enabled = true;
        app.model = FORMATS
            .iter()
            .position(|f| f.name == "Illustrious")
            .unwrap();
        app.sections[0].fields[0].state.free = "ぱっつん前髪".into();
        app.negatives = vec!["ぼやけた".into()];
        let ctx = egui::Context::default();
        app.generate(&ctx);
        for _ in 0..200 {
            app.poll_api(&ctx);
            if app.api_rx.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let req = srv.join().unwrap();
        assert!(
            req.contains("ぱっつん前髪") && req.contains("ぼやけた") && req.contains("Illustrious"),
            "{req}"
        );
        assert_eq!(
            app.output,
            "masterpiece, best quality, amazing quality, highres, 1girl, blunt bangs"
        );
        assert_eq!(
            app.output_neg,
            "worst quality, low quality, bad quality, bad anatomy, blurry"
        );
        assert!(app.api_status.contains("Illustrious"), "{}", app.api_status);
    }

    /// 修正ボタン: ポジティブ・ネガティブ・修正内容をAIに渡し、修正後が両方の欄に振り分けられる
    #[test]
    fn adjust_routes_ai_result_to_positive_and_negative() {
        let (port, srv) = mock_server(
            r#"{"choices":[{"message":{"content":"{\"positive\":\"1girl, silver hair\",\"negative\":\"blurry, text\"}"}}]}"#,
        );
        let mut app = App::blank();
        app.api = api_for(Provider::Gpt, port, "/v1");
        app.api.enabled = true;
        app.output = "1girl, black hair".into();
        app.output_neg = "blurry".into();
        app.adjust = "髪を銀髪に、文字は出さない".into();
        let ctx = egui::Context::default();
        app.adjust(&ctx);
        for _ in 0..200 {
            app.poll_api(&ctx);
            if app.api_rx.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let req = srv.join().unwrap();
        assert!(
            req.contains("1girl, black hair")
                && req.contains("blurry")
                && req.contains("髪を銀髪に"),
            "{req}"
        );
        assert_eq!(app.output, "1girl, silver hair");
        assert_eq!(app.output_neg, "blurry, text");
        assert!(app.adjust.is_empty());
    }

    /// API失敗時は、辞書による変換のみで出力し、修正は入力をそのまま追加する
    #[test]
    fn api_failure_falls_back_locally() {
        let (port, srv) =
            mock_server_status("400 Bad Request", r#"{"error":{"message":"bad key"}}"#);
        let mut app = App::blank();
        app.api = api_for(Provider::Gpt, port, "/v1");
        app.api.enabled = true;
        app.model = FORMATS
            .iter()
            .position(|f| f.name == "Stable Diffusion")
            .unwrap();
        app.sections[0].fields[0].state.tokens = vec![Tok {
            ja: "卵型の顔".into(),
            en: "oval face".into(),
        }];
        let ctx = egui::Context::default();
        app.generate(&ctx);
        for _ in 0..200 {
            app.poll_api(&ctx);
            if app.api_rx.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        srv.join().unwrap();
        assert!(app.output.contains("oval face"), "{}", app.output);
        assert!(
            app.api_status.contains("bad key") && app.api_status.contains("辞書"),
            "{}",
            app.api_status
        );
    }
    #[test]
    fn window_position_is_validated() {
        assert!(!window_is_usable(0.0, 0.0, 100.0, 100.0));
        assert!(!window_is_usable(-50000.0, 0.0, 1400.0, 1000.0));
        assert!(!window_is_usable(f32::NAN, 0.0, 1400.0, 1000.0));
    }

    /// 設定(ウィンドウ位置・オプション・API設定)は INI を経由して復元され、APIキーは平文で出ない
    #[test]
    fn settings_roundtrip_through_ini() {
        let mut a = App::blank();
        a.window = Some([120.0, 80.0, 1300.0, 900.0]);
        a.model = FORMATS.iter().position(|f| f.name == "NoobAI").unwrap();
        a.quality_tags = false;
        a.mj_no_params = false;
        a.aspect = 2;
        a.style = 1;
        a.chaos = 12.0;
        a.use_seed = true;
        a.seed = "12345".into();
        a.api.enabled = true;
        a.api.provider = Provider::Gemini;
        a.api.cfg[2].model = "gemini-x".into();
        a.api.cur_mut().key = "secret-key".into();
        let mut base = std::collections::BTreeMap::new();
        base.insert("api.claude_key".to_string(), "keep-me".to_string());
        let text = ini_render(&a.settings_to_map(base));
        assert!(!text.contains("secret-key"), "未ロックのキーは保存されない");
        assert!(
            text.contains("claude_key=keep-me"),
            "暗号化キーなど、既存の項目は保持される"
        );

        let mut b = App::blank();
        b.settings_from_map(&ini_parse(&text));
        assert_eq!(b.window, Some([120.0, 80.0, 1300.0, 900.0]));
        assert_eq!(FORMATS[b.model].name, "NoobAI");
        assert!(!b.quality_tags && !b.mj_no_params && b.use_seed && b.api.enabled);
        assert_eq!(
            (b.aspect, b.style, b.chaos, b.seed.as_str()),
            (2, 1, 12.0, "12345")
        );
        assert!(b.api.provider == Provider::Gemini);
        assert_eq!(b.api.cfg[2].model, "gemini-x");
    }

    #[test]
    fn state_json_no_longer_holds_settings() {
        let mut a = App::blank();
        a.window = Some([1.0, 2.0, 1300.0, 900.0]);
        a.api.enabled = true;
        let j = a.to_json();
        assert!(j.get("window").is_none() && j.get("api").is_none() && j.get("model").is_none());
    }

    #[test]
    fn fashion_field_uses_only_fashion_style() {
        let app = App::blank();
        let f = app
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.label == "ファッション系統")
            .expect("項目がある");
        assert_eq!(f.dicts, &["fashion_style"]);
        assert!(
            app.sections
                .iter()
                .flat_map(|s| &s.fields)
                .all(|f| f.label != "衣装全体")
        );
        let c = dict::category("fashion_style").unwrap();
        for en in ["gothic", "punk", "streetwear", "lolita fashion", "gyaru"] {
            assert!(c.entries.iter().any(|(e, _)| *e == en), "{en}");
        }
    }
    #[test]
    fn api_key_is_only_sent_over_https_or_localhost() {
        for ok in [
            "https://api.anthropic.com/v1",
            "http://localhost:11434/v1",
            "http://127.0.0.1:1234/v1",
            "http://[::1]:8080/v1",
        ] {
            assert!(check_base_url(ok).is_ok(), "{ok}");
        }
        for ng in [
            "http://example.com/v1",
            "http://192.168.0.5:8080/v1",
            "ftp://x",
            "api.openai.com/v1",
            "",
            "http://localhost@evil.com/v1",
            "http://127.0.0.1.evil.com/v1",
        ] {
            assert!(check_base_url(ng).is_err(), "{ng}");
        }
        // 危険なURLでは、通信せずにエラーになる
        let mut api = ApiSettings::default();
        api.cur_mut().key = "k".into();
        api.cur_mut().base_url = "http://example.com/v1".into();
        assert!(
            llm_generate(&api, &FORMATS[0], "x", "")
                .unwrap_err()
                .contains("https")
        );
        assert!(fetch_models(&api).unwrap_err().contains("https"));
    }

    #[test]
    fn redirects_are_not_followed() {
        // リダイレクト先にキーが渡らないよう、3xxは追わずにエラーとして扱う
        let (port, srv) = mock_server_status("302 Found", r#"{"error":{"message":"moved"}}"#);
        let r = fetch_models(&api_for(Provider::Claude, port, "/v1"));
        srv.join().unwrap();
        assert!(r.unwrap_err().contains("HTTP 302"));
    }

    #[test]
    fn bom_and_oversized_files_are_handled() {
        let dir = std::env::temp_dir().join(format!("pg_bom_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // メモ帳が付けるBOM付きでも読める
        let ini = dir.join("a.ini");
        std::fs::write(&ini, "\u{feff}[api]\nclaude_key=abcd\n").unwrap();
        assert_eq!(
            ini_read(&ini).get("api.claude_key").map(String::as_str),
            Some("abcd")
        );
        let json = dir.join("a.json");
        std::fs::write(&json, "\u{feff}{\"a\":1}").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read_text_limited(&json, 1000).unwrap())
                .unwrap()["a"],
            1
        );
        // 大きすぎるファイルは読まない
        assert!(read_text_limited(&json, 3).is_none());
        // INIの書き込みは一時ファイルを残さない
        let mut map = std::collections::BTreeMap::new();
        map.insert("api.x".to_string(), "1".to_string());
        ini_write(&ini, &map).unwrap();
        assert!(!dir.join("a.ini.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_must_be_numeric_and_history_is_capped() {
        let mut app = App::blank();
        app.model = 0;
        app.mj_no_params = false;
        app.use_seed = true;
        app.seed = "abc; --no x".into();
        app.finish("a".into(), String::new());
        assert!(!app.output.contains("--seed"), "{}", app.output);
        app.seed = "12345".into();
        app.finish("a".into(), String::new());
        assert!(app.output.contains("--seed 12345"), "{}", app.output);
        for _ in 0..80 {
            app.finish("a".into(), String::new());
        }
        assert_eq!(app.history.len(), 50);
    }

    #[test]
    fn every_field_can_randomize_without_panicking() {
        let mut app = App::blank();
        let mut rng = Rng::new();
        for sec in &mut app.sections {
            for fl in &mut sec.fields {
                for _ in 0..30 {
                    fl.randomize(&mut rng);
                    // 空白でなければ英語が入っている
                    if let Some(t) = fl.state.tokens.first() {
                        assert!(!t.en.is_empty(), "{}/{}", sec.title, fl.label);
                    }
                }
            }
        }
        assert_eq!(Rng::new().pick(&[]), "");
    }

    #[test]
    fn dictionary_is_clean() {
        let mut seen = std::collections::HashSet::new();
        for c in dict::all() {
            assert!(seen.insert(c.id), "カテゴリIDの重複: {}", c.id);
            assert!(!c.entries.is_empty(), "{}", c.id);
            for (en, ja) in c.entries {
                assert!(
                    !en.trim().is_empty() && !ja.trim().is_empty(),
                    "{}: 空の語",
                    c.id
                );
                assert!(
                    !en.contains(['\n', '"']) && !ja.contains('\n'),
                    "{}: {en}",
                    c.id
                );
            }
        }
        // 項目が参照する辞書IDは、すべて存在する
        for sec in build_sections() {
            for fl in &sec.fields {
                // 先頭が現行の辞書ID (2つ目以降は旧辞書用の互換ID で、無くてもよい)
                if let Some(id) = fl.dicts.first() {
                    assert!(
                        dict::category(id).is_some(),
                        "{} が参照する辞書がありません: {id}",
                        fl.label
                    );
                }
            }
        }
    }
    #[test]
    fn favorites_add_name_recall_and_persist() {
        let mut app = App::blank();
        // 空のときは登録できない
        assert!(app.add_favorite("x").is_err());
        app.output = "1girl, long hair".into();
        app.output_neg = "blurry".into();
        app.model = FORMATS
            .iter()
            .position(|f| f.name == "Illustrious")
            .unwrap();
        app.add_favorite("  銀髪の子  ").unwrap();
        app.output = "2girls".into();
        app.output_neg.clear();
        app.model = 0;
        app.add_favorite("").unwrap(); // 名前が空なら自動で付く
        assert_eq!(app.favorites.len(), 2);
        assert_eq!(app.favorites[0].name, "お気に入り 2");
        assert_eq!(app.favorites[1].name, "銀髪の子");

        // 保存→再読み込みで復元される
        let json = app.to_json();
        let mut b = App::blank();
        b.load_json(&json);
        assert_eq!(b.favorites, app.favorites);

        // 呼び出すと、ポジティブ・ネガティブ・出力モデルが戻る
        b.recall_favorite(1);
        assert_eq!(
            (b.output.as_str(), b.output_neg.as_str()),
            ("1girl, long hair", "blurry")
        );
        assert_eq!(FORMATS[b.model].name, "Illustrious");
        b.recall_favorite(99); // 範囲外でも落ちない

        // 名前の長さは制限される
        b.add_favorite(&"あ".repeat(200)).unwrap();
        assert_eq!(b.favorites[0].name.chars().count(), 60);
    }

    #[test]
    fn favorites_are_capped() {
        let mut app = App::blank();
        app.output = "a".into();
        for i in 0..(MAX_FAVORITES + 20) {
            app.add_favorite(&format!("n{i}")).unwrap();
        }
        assert_eq!(app.favorites.len(), MAX_FAVORITES);
        assert_eq!(app.favorites[0].name, format!("n{}", MAX_FAVORITES + 19));
    }
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pg_fav_test_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn favorite_markdown_roundtrip() {
        let f = Favorite {
            name: "銀髪の子".into(),
            positive: "1girl, silver hair\nline2 ```code``` end".into(),
            negative: String::new(),
            model: "Illustrious".into(),
            file: String::new(),
        };
        let md = fav_render(&f);
        assert!(md.starts_with("# 銀髪の子\n"));
        assert!(md.contains("## ポジティブ") && md.contains("## ネガティブ"));
        assert_eq!(fav_parse(&md, "x"), f);
        // CRLFでも読める
        assert_eq!(fav_parse(&md.replace('\n', "\r\n"), "x"), f);
        // 見出しだけ・コードフェンス無しの手書きMDも読める
        let hand = "# 手書き\n- モデル: Pony\n\n## ポジティブ\nscore_9, 1girl\n\n## ネガティブ\nbad hands\n";
        let h = fav_parse(hand, "x");
        assert_eq!(
            (
                h.name.as_str(),
                h.positive.as_str(),
                h.negative.as_str(),
                h.model.as_str()
            ),
            ("手書き", "score_9, 1girl", "bad hands", "Pony")
        );
        // 名前が無ければファイル名を使う
        assert_eq!(
            fav_parse("## ポジティブ\n```\na\n```\n", "stem").name,
            "stem"
        );
    }

    #[test]
    fn favorite_files_are_saved_renamed_deleted_and_loaded() {
        let dir = temp_dir("io");
        let mut a = Favorite {
            name: "a/b:c*?".into(),
            positive: "p1".into(),
            negative: "n1".into(),
            model: "Pony".into(),
            file: String::new(),
        };
        fav_write(&dir, &mut a).unwrap();
        assert_eq!(a.file, "a_b_c__.md");
        // 同名は連番になり、上書きしない
        let mut b = Favorite {
            name: "a/b:c*?".into(),
            positive: "p2".into(),
            negative: String::new(),
            model: "".into(),
            file: String::new(),
        };
        fav_write(&dir, &mut b).unwrap();
        assert_eq!(b.file, "a_b_c__ (2).md");
        // 既存ファイルの更新は同じファイル名のまま
        b.positive = "p2 edited".into();
        fav_write(&dir, &mut b).unwrap();
        assert_eq!(b.file, "a_b_c__ (2).md");
        // .md 以外・フォルダ・壊れたファイルは無視
        std::fs::write(dir.join("memo.txt"), "x").unwrap();
        std::fs::write(dir.join("empty.md"), "# 空\n").unwrap();
        std::fs::create_dir_all(dir.join("sub.md")).unwrap();
        let list = fav_scan(&dir).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|f| f.file == a.file
            && f.positive == "p1"
            && f.negative == "n1"
            && f.model == "Pony"));
        assert!(
            list.iter()
                .any(|f| f.file == b.file && f.positive == "p2 edited")
        );
        // 削除
        fav_delete(&dir, &a);
        assert_eq!(fav_scan(&dir).unwrap().len(), 1);
        // パス区切りを含むファイル名では何も消さない
        std::fs::write(dir.join("keep.md"), "# k\n").unwrap();
        fav_delete(
            &dir,
            &Favorite {
                file: "../keep.md".into(),
                ..a.clone()
            },
        );
        assert!(dir.join("keep.md").exists());
        // フォルダが無ければ空
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(fav_scan(&dir).unwrap().len(), 0);
    }

    #[test]
    fn favorite_file_names_are_safe() {
        assert_eq!(fav_file_stem("CON"), "_CON");
        assert_eq!(fav_file_stem("com1"), "_com1");
        assert_eq!(fav_file_stem(" ... "), "fav");
        assert_eq!(fav_file_stem(r"..\..\evil"), "_.._evil");
        assert!(
            !fav_file_ok("../x.md")
                && !fav_file_ok("a\\b.md")
                && !fav_file_ok("x.txt")
                && !fav_file_ok("")
                && fav_file_ok("ok.md")
        );
    }

    #[test]
    fn reload_migrates_json_favorites_to_md() {
        // state.json 由来(file空)のお気に入りは to_json に残り、MD保存後は残らない
        let mut app = App::blank();
        app.output = "x".into();
        app.add_favorite("m").unwrap();
        assert_eq!(app.to_json()["favorites"].as_array().unwrap().len(), 1);
        app.favorites[0].file = "m.md".into();
        assert_eq!(app.to_json()["favorites"].as_array().unwrap().len(), 0);
    }
    #[test]
    fn count_gender_age_tags_and_layout() {
        assert_eq!(count_tag(0, Some(1)), "solo");
        assert_eq!(count_tag(1, Some(1)), "2girls");
        assert_eq!(count_tag(1, Some(0)), "2boys");
        assert_eq!(count_tag(2, None), "3people");
        assert_eq!(count_tag(3, Some(1)), "multiple girls");
        let mut a = App::blank();
        a.gender = Some(1);
        a.age = Some(1);
        a.count = Some(0);
        let (body, _) = a.collect();
        assert!(body.starts_with("solo, female, young adult"), "{body}");
        // 保存データにも人数が残る
        let mut b = App::blank();
        b.load_json(&a.to_json());
        assert_eq!(b.count, Some(0));
        let s = b.snapshot("x".into());
        b.count = None;
        b.restore(&s);
        assert_eq!(b.count, Some(0));
        // 表示順: 画風・品質・技術 → キャラクター → 顔 → 身体 → 衣装 → ポーズ → 感情 → シーン
        let titles: Vec<&str> = LAYOUT.iter().map(|x| x.map_or("キャラクター", |i| b.sections[i].title)).collect();
        assert_eq!(titles, ["画風・品質・技術", "キャラクター", "顔・頭部", "身体", "衣装・服装", "ポーズ・動作", "感情・表現", "シーン・背景"]);
        assert_eq!(NAV_TARGET[0], 6);
        // 落ち着いた は英語タグになる
        assert_eq!(
            dict::lookup(&["face_mood"], "落ち着いた"),
            Some("calm and composed")
        );
        assert_eq!(
            dict::lookup(&["scene_situation"], "街中"),
            Some("city street")
        );
    }

    #[test]
    fn context_text_lists_selected_items() {
        let mut a = App::blank();
        a.gender = Some(1);
        a.count = Some(0);
        a.sections[0].fields[0].state.free = "丸顔".into();
        let t = a.context_text();
        assert!(t.starts_with("※ Midjourney: パラメータ"), "{t}");
        assert!(
            t.contains(
                "
# 選択内容 (出力モデル: Midjourney)"
            ),
            "{t}"
        );
        a.mj_no_params = false;
        assert!(a.context_text().starts_with("# 選択内容"));
        a.mj_no_params = true;
        a.model = FORMATS.iter().position(|f| f.name == "Pony").unwrap();
        assert!(
            a.context_text()
                .starts_with("# 選択内容 (出力モデル: Pony)")
        );
        a.model = 0;
        assert!(
            t.contains("- 人数: 1人 (solo)")
                && t.contains("- 性別: 女性 (female)")
                && t.contains("- 輪郭・鼻: 丸顔"),
            "{t}"
        );
        assert!(t.find("## キャラクター設定") < t.find("## 顔・頭部"));
        assert_eq!(
            App {
                gender: None,
                ..App::blank()
            }
            .context_text(),
            ""
        );
    }

    #[test]
    fn copy_modes_english_and_words_only() {
        // 全ての大分類・項目に英語名がある
        for s in build_sections() {
            assert!(en_label(s.title).is_ascii(), "{}", s.title);
            for fl in &s.fields {
                assert!(en_label(fl.label).is_ascii(), "{}", fl.label);
            }
        }
        let mut a = App::blank();
        a.gender = Some(1);
        a.count = Some(0);
        a.age = Some(1);
        a.sections[0].fields[0].state.tokens = vec![Tok { ja: "丸顔".into(), en: "round face".into() }];
        a.sections[0].fields[1].state.tokens = vec![Tok { ja: "ふっくらした唇".into(), en: "full lips".into() }];
        a.sections[1].fields[0].state.tokens = vec![Tok { ja: "丸顔".into(), en: "Round face".into() }];
        a.negatives = vec!["blurry".into()];
        a.copy_mode = 1;
        let t = a.context_text();
        assert!(t.contains("# Selection (target model:") && t.contains("## Character") && t.contains("## Face & Head"), "{t}");
        assert!(t.contains("- Count: solo") && t.contains("- Gender: female") && t.contains("- Face outline & nose: round face"), "{t}");
        assert!(t.contains("## Negative") && t.is_ascii(), "{t}");
        // 英単語のみ: 分類なし。重複 (大文字小文字違い) は1つ。ネガティブは別の行
        a.copy_mode = 2;
        let w = a.context_text();
        assert_eq!(w, format!("solo, female, {}, round face, full lips
Negative prompt: blurry", AGE_TAGS[1]), "{w}");
        a.negatives.clear();
        assert!(!a.context_text().contains("Negative"));
        // 既定は従来どおり日本語の見出し
        a.copy_mode = 0;
        assert!(a.context_text().contains("## 顔・頭部"));
        // 何も選んでいなければ、どの形式でも空
        for mode in 0..COPY_MODES.len() {
            let e = App { gender: None, copy_mode: mode, ..App::blank() };
            assert_eq!(e.context_text(), "");
        }
    }

    #[test]
    fn negation_terms_move_to_negative_prompt_where_supported() {
        assert_eq!(negation_target("no background").as_deref(), Some("background"));
        assert_eq!(negation_target("Without hat").as_deref(), Some("hat"));
        assert_eq!(negation_target("no humans"), None);
        assert_eq!(negation_target("no-collar blazer school uniform"), None);
        assert_eq!(negation_target("nose"), None);
        let tok = |en: &str| Tok { ja: en.into(), en: en.into() };
        let mut a = App::blank();
        a.gender = Some(1);
        a.sections[5].fields[0].state.tokens = vec![tok("no background"), tok("white background")];
        a.sections[5].fields[1].state.tokens = vec![tok("no humans")];
        a.negatives = vec!["blurry".into()];
        for name in ["Midjourney", "Stable Diffusion", "Pony"] {
            a.model = FORMATS.iter().position(|f| f.name == name).unwrap();
            let (body, neg) = a.collect();
            assert!(!body.contains("no background") && body.contains("white background") && body.contains("no humans"), "{name}: {body}");
            assert_eq!(neg, "blurry, background", "{name}");
        }
        // Midjourney では --no に入る
        a.model = 0;
        a.mj_no_params = false;
        let (body, neg) = a.collect();
        a.finish(body, neg);
        assert!(a.output.contains("--no blurry, background"), "{}", a.output);
        // ネガティブが無い DALL·E (自然文) では本文に残す
        a.model = FORMATS.iter().position(|f| f.name == "DALL·E").unwrap();
        let (body, neg) = a.collect();
        assert!(body.contains("no background") && neg == "blurry");
        // 英単語のみのコピーも同じ扱い
        a.model = 0;
        a.copy_mode = 2;
        let w = a.context_text();
        assert!(w.contains("white background") && !w.contains("no background") && w.ends_with("Negative prompt: blurry, background"), "{w}");
    }

    #[test]
    fn default_tokens_are_prefilled_removable_and_restored_on_reset() {
        let mut a = App::blank();
        a.reset();
        let find = |a: &App, l: &str| {
            a.sections.iter().flat_map(|s| s.fields.iter()).find(|f| f.label == l).unwrap().state.tokens.iter().map(|t| t.en.clone()).collect::<Vec<_>>()
        };
        assert_eq!(find(&a, "品質"), ["perfect", "masterpiece"]);
        assert_eq!(find(&a, "雰囲気・色彩"), ["colorful", "full color"]);
        a.sections.iter_mut().flat_map(|s| s.fields.iter_mut()).find(|f| f.label == "品質").unwrap().state.tokens.clear();
        assert!(find(&a, "品質").is_empty());
        // 古い保存データ (項目なし) では既定の語が入る
        a.load_json(&serde_json::json!({}));
        assert_eq!(find(&a, "品質"), ["perfect", "masterpiece"]);
    }

    #[test]
    fn compound_and_free_text_words_become_english() {
        assert_eq!(dict::lookup_compound(&[], "カラー色彩").as_deref(), Some("color, colors"));
        assert_eq!(dict::lookup_compound(&[], "背景なし").as_deref(), Some("no background"));
        assert_eq!(dict::lookup_compound(&[], "zzzz存在しない語"), None);
        let mut a = App::blank();
        a.api.enabled = false;
        a.other = "カラー色彩 背景なし".into();
        let (pos, neg) = a.collect();
        assert!(pos.contains("color, colors"), "{pos}");
        assert!(neg.contains("background"), "{neg}");
    }

    #[test]
    fn no_background_never_stays_japanese() {
        for model in ["Midjourney", "Pony", "DALL·E"] {
            for copy_mode in 0..COPY_MODES.len() {
                let mut a = App::blank();
                a.api.enabled = false;
                a.model = FORMATS.iter().position(|f| f.name == model).unwrap();
                a.copy_mode = copy_mode;
                let fl = a.sections.iter_mut().flat_map(|s| s.fields.iter_mut()).find(|f| f.label == "シチュエーション").unwrap();
                fl.state.free = "背景なし".into();
                let (pos, neg) = a.collect();
                a.finish(pos.clone(), neg.clone());
                a.other = "背景なし".into();
                a.appearance = "背景なし".into();
                for text in [&pos, &neg, &a.output, &a.output_neg, &a.words_text(), &a.context_text_en()] {
                    assert!(!text.contains("背景"), "{model}/{copy_mode}: {text}");
                }
            }
        }
    }

    #[test]
    fn copy_text_starts_with_request_for_the_selected_model() {
        let mut a = App::blank();
        a.gender = Some(1);
        for model in ["Midjourney", "Pony", "DALL·E"] {
            a.model = FORMATS.iter().position(|f| f.name == model).unwrap();
            for mode in 0..COPY_MODES.len() {
                a.copy_mode = mode;
                let t = a.copy_text();
                let head = format!("貴方は、プロンプトエンジニアです。
以下の内容を英語の「{model}」用のプロンプトにしてください

");
                assert!(t.starts_with(&head) && t.len() > head.len(), "{t}");
            }
        }
        assert_eq!(App { gender: None, ..App::blank() }.copy_text(), "");
    }

    #[test]
    fn basic_color_words_resolve_to_english() {
        let ids = ["mood_color", "scene_mood", "color_palette"];
        for (ja, en) in [("カラー", "color"), ("色彩", "colors"), ("色彩豊か", "colorful"), ("色彩豊かな", "colorful"), ("カラフル", "colorful tones"), ("フルカラー", "full color")] {
            assert_eq!(dict::lookup(&ids, ja), Some(en), "{ja}");
        }
    }

    #[test]
    fn pony_positive_starts_with_score_tags() {
        let pony = FORMATS.iter().find(|f| f.name == "Pony").unwrap();
        let out = compose_positive(pony.prefix, "1girl, long_hair, score_9, source_anime, smile");
        assert_eq!(out, "score_9, score_8_up, score_7_up, score_6_up, source_anime, 1girl, long hair, smile", "{out}");
        let mut a = App::blank();
        a.model = FORMATS.iter().position(|f| f.name == "Pony").unwrap();
        a.quality_tags = true;
        a.finish("1girl, long_hair".into(), "bad_hands".into());
        assert!(a.output.starts_with("score_9, score_8_up"), "{}", a.output);
        assert!(a.output_neg.starts_with("score_6, score_5, score_4"), "{}", a.output_neg);
    }

    #[test]
    fn score_tags_lead_the_negative_and_keep_underscores() {
        let pony = FORMATS.iter().find(|f| f.name == "Pony").unwrap();
        let out = compose_negative(pony.neg, "bad_hands, score_6, blurry, score_4, Bad Hands");
        assert_eq!(out, "score_6, score_5, score_4, text, watermark, signature, bad hands, blurry", "{out}");
        assert_eq!(compose_negative("", "lowres, score_5"), "score_5, lowres");
    }

    #[test]
    fn negative_dictionary_picker_edits_negatives() {
        let n = dict::category("negative_prompt").unwrap();
        assert!(n.kinds.len() >= 5 && n.entries.iter().any(|(en, _)| *en == "extra fingers"));
        let mut fl = negative_picker_field(&["blurry".to_string(), "ぼやけた".to_string()]);
        assert!(fl.has("blurry") && !fl.has("extra fingers"));
        fl.toggle("extra fingers", "余分な指");
        fl.toggle("blurry", "ぼやけた");
        let back: Vec<String> = fl.state.tokens.iter().map(|t| t.en.clone()).collect();
        assert_eq!(back, ["ぼやけた", "extra fingers"]);
    }

    #[test]
    fn section_groups_cover_all_fields() {
        for s in build_sections() {
            assert_eq!(s.groups.iter().map(|g| g.1).sum::<usize>(), s.fields.len(), "{}", s.title);
        }
    }

    #[test]
    fn dictionary_file_is_parsed_and_bad_files_are_rejected() {
        let ok = r#"{"categories":[{"id":"nose","name":"鼻","entries":[["button nose","団子鼻"]]}]}"#;
        let cats = dict::parse(ok).unwrap();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0].entries, &[("button nose", "団子鼻")]);
        assert!(dict::parse("{").is_err());
        assert!(dict::parse(r#"{"categories":[]}"#).is_err());
        assert!(dict::parse(r#"{"categories":[{"id":"x","entries":[]}]}"#).is_err());
        assert!(dict::parse(r#"{"categories":[{"id":"x","entries":[["a"]]}]}"#).is_err());
        let dup = r#"{"categories":[{"id":"x","entries":[["a","あ"]]},{"id":"x","entries":[["b","い"]]}]}"#;
        assert!(dict::parse(dup).is_err());
        // Rustソース形式 (dict.rs と同じ書き方) も読める。コメント・エスケープ・複数行の組に対応
        let rs = r#"// c
pub static CATEGORIES: &[Category] = &[
    Category {
        id: "nose",
        name: "鼻",
        entries: &[
            ("button nose", "団子鼻"), /* x */ (
                "say \"hi\"",
                "や",
            ),
        ],
    },
    Category { id: "b", name: "B", entries: &[("x", "え")] },
];"#;
        let c = dict::parse_file("a.rs", rs).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].name, "鼻");
        assert_eq!(c[0].entries, &[("button nose", "団子鼻"), ("say \"hi\"", "や")]);
        assert_eq!(c[1].id, "b");
        assert!(dict::parse_file("a.rs", r#"Category { id: "z", entries: &[("only")] }"#).is_err());
        assert!(dict_file_ok("dic_all.rs") && !dict_file_ok("a.rs.txt"));
        // 同梱の初期辞書は読み込める
        assert!(dict::parse(dict::SEED).unwrap().len() > 20);
        assert!(dict_file_ok("a.json") && !dict_file_ok("../a.json") && !dict_file_ok("a.txt") && !dict_file_ok("a\\b.json"));
    }

    #[test]
    fn template_rs_is_a_valid_dictionary() {
        let t = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Dict/template.rs")).unwrap();
        let c = dict::parse_file("template.rs", &t).unwrap();
        assert_eq!(c.iter().map(|x| x.id).collect::<Vec<_>>(), ["face_nose", "nose", "scene_situation"]);
    }

    #[test]
    fn kinds_split_entries_consistently_in_json_and_rs() {
        // 種類の語数の合計は語の総数と同じ。.rs 形式でも同じ区切りになる
        let t = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Dict/dict_v2.rs")).unwrap();
        let rs = dict::parse_file("dict_v2.rs", &t).unwrap();
        let json = dict::parse(dict::SEED).unwrap();
        assert!(json.iter().filter(|c| !c.kinds.is_empty()).count() > 30);
        for (a, b) in json.iter().zip(rs.iter()) {
            assert_eq!(a.kinds, b.kinds, "{}", a.id);
            assert_eq!(a.entries, b.entries, "{}", a.id);
            if !a.kinds.is_empty() {
                assert!(a.kinds.len() >= 2 && a.kinds.iter().all(|(_, n)| *n > 0), "{}", a.id);
                assert_eq!(a.kinds.iter().map(|(_, n)| n).sum::<usize>(), a.entries.len(), "{}", a.id);
            }
        }
        // 種類の宣言と3つ目の書き方
        let c = dict::parse(r#"{"categories":[{"id":"x","name":"X","kinds":["A","B"],"entries":[["b1","び","B"],["a1","あ","A"],["z","ぜ"]]}]}"#).unwrap();
        assert_eq!(c[0].kinds, &[("A", 1), ("B", 1), ("その他", 1)]);
        assert_eq!(c[0].entries.iter().map(|e| e.0).collect::<Vec<_>>(), ["a1", "b1", "z"]);
        assert!(dict::parse(r#"{"categories":[{"id":"x","kinds":["A"],"entries":[["a","あ","C"]]}]}"#).is_err());
        let r = dict::parse_file("a.rs", r#"Category { id: "x", name: "X", kinds: &["A", "B"], entries: &[("a", "あ", "B"), ("b", "び", "A")] }"#).unwrap();
        assert_eq!(r[0].kinds, &[("A", 1), ("B", 1)]);
        assert_eq!(r[0].entries[0].0, "b");
    }

    #[test]
    fn default_dictionary_has_no_duplicate_words() {
        let norm = |s: &str| s.to_lowercase().replace(['_', '-', '\''], " ").split_whitespace().collect::<Vec<_>>().join(" ");
        let mut en_seen = std::collections::HashMap::new();
        for c in dict::parse(dict::SEED).unwrap() {
            // ネガティブ用カテゴリは、元の場所の語をそのまま残してまとめ直したものなので、重複を許す
            if c.id == "negative_prompt" {
                continue;
            }
            let mut ja_seen = std::collections::HashSet::new();
            for (en, ja) in c.entries {
                // 英語は辞書全体で1か所だけ、日本語は同じカテゴリ内で重複しない
                if let Some(prev) = en_seen.insert(norm(en), c.id) {
                    panic!("英語が重複: {en} ({prev} と {})", c.id);
                }
                assert!(ja_seen.insert(ja.trim()), "{}: 日本語が重複: {ja}", c.id);
            }
        }
    }

    #[test]
    fn dict_v2_rs_matches_default_dictionary_and_covers_every_field() {
        let t = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Dict/dict_v2.rs")).unwrap();
        let rs = dict::parse_file("dict_v2.rs", &t).unwrap();
        let json = dict::parse(dict::SEED).unwrap();
        assert_eq!(rs.len(), json.len());
        assert_eq!(
            rs.iter().map(|x| x.entries.len()).sum::<usize>(),
            json.iter().map(|x| x.entries.len()).sum::<usize>()
        );
        // 全ての入力欄に、先頭のIDで辞書が結びつき、語が1つ以上ある
        let ids: std::collections::HashSet<&str> = rs.iter().map(|c| c.id).collect();
        for fl in build_sections().iter().flat_map(|s| s.fields.iter()) {
            assert!(ids.contains(fl.dicts[0]), "{}", fl.label);
        }
        // どのカテゴリも、どこかの入力欄に結びついている
        let used: std::collections::HashSet<&str> =
            build_sections().iter().flat_map(|s| s.fields.iter()).map(|f| f.dicts[0]).collect();
        // 末尾のネガティブ用カテゴリだけは、入力項目ではなくネガティブプロンプト欄の辞書ボタンに結びつく
        assert_eq!(used.len() + 1, rs.len());
        assert_eq!(rs.last().unwrap().id, "negative_prompt");
    }

    #[test]
    fn dict_v1_rs_is_a_valid_dictionary() {
        let t = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Dict/dict_v1.rs")).unwrap();
        let c = dict::parse_file("dict_v1.rs", &t).unwrap();
        assert_eq!(c.len(), 131);
        assert_eq!(c.iter().map(|x| x.entries.len()).sum::<usize>(), 3376);
        // カテゴリ内に英語の重複が無い
        for cat in &c {
            let mut seen = std::collections::HashSet::new();
            for (en, _) in cat.entries {
                assert!(seen.insert(en.to_lowercase().replace('_', " ")), "{}: {en}", cat.id);
            }
        }
    }

    #[test]
    fn random_can_pick_blank_and_randomize_all_button_logic() {
        let mut rng = Rng::new();
        let (mut some, mut none) = (0, 0);
        for _ in 0..2000 {
            match rng.opt(3) {
                Some(i) => {
                    assert!(i < 3);
                    some += 1;
                }
                None => none += 1,
            }
        }
        assert!(some > 0 && none > 0, "{some} {none}");
        // 項目のランダムでも、語が入る場合と空白になる場合がある
        let mut app = App::blank();
        let (mut filled, mut empty) = (0, 0);
        for _ in 0..3000 {
            app.randomize_all();
            let f = &app.sections[5].fields[0]; // 選択肢の少ない項目
            if f.state.tokens.is_empty() { empty += 1 } else { filled += 1 }
        }
        assert!(filled > 0 && empty > 0, "{filled} {empty}");
    }

    #[test]
    fn simple_mode_shows_only_listed_fields_and_randomizes_only_them() {
        let app = App::blank();
        let all: Vec<&Field> = app.sections.iter().flat_map(|s| s.fields.iter()).collect();
        let simple = all.iter().filter(|f| f.simple).count();
        assert_eq!(simple, SIMPLE_FIELDS.len(), "SIMPLE_FIELDS に存在しない項目名がある");
        assert!(simple < all.len() / 2);
        let mut app = App::blank();
        app.simple_mode = true;
        for _ in 0..50 {
            app.randomize_all();
        }
        let hidden_filled = app.sections.iter().flat_map(|s| s.fields.iter()).any(|f| !f.simple && !f.state.tokens.is_empty());
        assert!(!hidden_filled);
        let mut map = std::collections::BTreeMap::new();
        map = app.settings_to_map(map);
        assert_eq!(map.get("ui.mode").map(String::as_str), Some("simple"));
    }
}
