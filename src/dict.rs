//! プロンプト辞書の読み込み。
//! 辞書の中身は Dict フォルダの JSON (既定は Dict/dictionary.json) にあり、メモ帳などで編集できる。
//! 形式: {"name": "...", "sources": ["出典", ...], "categories": [{"id": "...", "name": "...", "kinds": ["種類A", "種類B"], "entries": [["english", "日本語", "種類A"], ...]}]}
//! 各カテゴリの先頭で名前(name)と、中に入っている単語の種類(kinds)を宣言する。語の3つ目に種類名を書くと、
//! 辞書ピッカーが種類ごとに区切って表示し、種類ごとにまとめて選べる。kinds と3つ目は省略できる (省略時は区切りなし)。
//! exe には初期の辞書(Dict/dictionary.json)を1つだけ同梱し、ファイルが無い・壊れているときの復旧にだけ使う。

pub type Entry = (&'static str, &'static str); // (英語プロンプト, 日本語)

pub struct Category {
    pub id: &'static str,
    pub name: &'static str,
    pub entries: &'static [Entry],
    /// 単語の種類: (種類名, 語の数)。entries は種類の順に並んでいて、数の合計が語の総数になる。種類を宣言しないカテゴリは空
    pub kinds: &'static [(&'static str, usize)],
}

/// 同梱の初期辞書 (JSON)
pub const SEED: &str = include_str!("../Dict/dictionary.json");

/// 使用中の辞書。文字列は読み込み時に解放せず保持する (切り替えは稀なので量は小さい)
static ACTIVE: std::sync::RwLock<&'static [Category]> = std::sync::RwLock::new(&[]);

static INIT: std::sync::Once = std::sync::Once::new();

/// いま使う辞書の全カテゴリ (まだ読み込まれていなければ同梱の初期辞書)
pub fn all() -> &'static [Category] {
    INIT.call_once(|| store(parse(SEED).unwrap_or_default()));
    ACTIVE.read().map_or(&[], |g| *g)
}

fn store(cats: Vec<Category>) {
    if let Ok(mut g) = ACTIVE.write() {
        *g = Box::leak(cats.into_boxed_slice());
    }
}

/// 辞書を差し替える
pub fn set_active(cats: Vec<Category>) {
    INIT.call_once(|| {});
    store(cats);
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// 辞書(JSON)を読む。形式が不正なら理由を返す
pub fn parse(text: &str) -> Result<Vec<Category>, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("JSONを読めません: {e}"))?;
    from_value(&v)
}

/// ファイル名の拡張子 (.json / .rs) に合わせて読む
pub fn parse_file(name: &str, text: &str) -> Result<Vec<Category>, String> {
    if name.to_lowercase().ends_with(".rs") { parse_rs(text) } else { parse(text) }
}

/// Rustソース形式の辞書 (`Category { id: "..", name: "..", kinds: &["種類", ..], entries: &[("en", "ja", "種類"), ..] }` の並び。
/// kinds と各語の3つ目は省略できる) を読む。
/// コンパイルはせず、コメントを除いた文字列リテラルだけを順に拾う
pub fn parse_rs(text: &str) -> Result<Vec<Category>, String> {
    enum T {
        Id(String),
        Str(String),
        Open,
        Close,
    }
    let ch: Vec<char> = text.chars().collect();
    let mut toks: Vec<T> = Vec::new();
    let mut i = 0;
    while i < ch.len() {
        let c = ch[i];
        if c == '/' && ch.get(i + 1) == Some(&'/') {
            while i < ch.len() && ch[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && ch.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < ch.len() && !(ch[i] == '*' && ch[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' {
            let mut s = String::new();
            i += 1;
            loop {
                let Some(&x) = ch.get(i) else { return Err("文字列が閉じていません".into()) };
                i += 1;
                match x {
                    '"' => break,
                    '\\' => {
                        let Some(&e) = ch.get(i) else { return Err("文字列が閉じていません".into()) };
                        i += 1;
                        match e {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '0' => s.push('\0'),
                            '\n' => {
                                while ch.get(i).is_some_and(|c| c.is_whitespace()) {
                                    i += 1;
                                }
                            }
                            other => s.push(other),
                        }
                    }
                    other => s.push(other),
                }
            }
            toks.push(T::Str(s));
        } else if c == '[' || c == '(' {
            toks.push(T::Open);
            i += 1;
        } else if c == ']' || c == ')' {
            toks.push(T::Close);
            i += 1;
        } else if c.is_alphabetic() || c == '_' {
            let s = i;
            while i < ch.len() && (ch[i].is_alphanumeric() || ch[i] == '_') {
                i += 1;
            }
            toks.push(T::Id(ch[s..i].iter().collect()));
        } else {
            i += 1;
        }
    }
    // id / name / kinds / entries を順に拾う
    let mut cats: Vec<serde_json::Value> = Vec::new();
    let (mut id, mut name): (Option<String>, Option<String>) = (None, None);
    let mut kinds: Vec<String> = Vec::new();
    let mut k = 0;
    while k < toks.len() {
        match (&toks[k], toks.get(k + 1)) {
            (T::Id(w), Some(T::Str(s))) if w == "id" => {
                id = Some(s.clone());
                name = None;
                kinds.clear();
                k += 2;
            }
            (T::Id(w), Some(T::Str(s))) if w == "name" => {
                name = Some(s.clone());
                k += 2;
            }
            (T::Id(w), _) if w == "kinds" && id.is_some() => {
                k += 1;
                let mut depth = 0i32;
                while k < toks.len() {
                    match &toks[k] {
                        T::Open => depth += 1,
                        T::Close => {
                            depth -= 1;
                            if depth <= 0 {
                                k += 1;
                                break;
                            }
                        }
                        T::Str(s) => kinds.push(s.clone()),
                        T::Id(_) => {}
                    }
                    k += 1;
                }
            }
            (T::Id(w), _) if w == "entries" && id.is_some() => {
                let cid = id.take().unwrap_or_default();
                k += 1;
                let mut depth = 0i32;
                let mut cur: Vec<&str> = Vec::new();
                let mut entries: Vec<serde_json::Value> = Vec::new();
                while k < toks.len() {
                    match &toks[k] {
                        T::Open => {
                            depth += 1;
                            cur.clear();
                        }
                        T::Close => {
                            if depth == 2 {
                                if !(2..=3).contains(&cur.len()) {
                                    return Err(format!("{cid}: 語が (英語, 日本語) か (英語, 日本語, 種類) の組になっていません"));
                                }
                                entries.push(serde_json::json!(cur));
                            }
                            depth -= 1;
                            if depth <= 0 {
                                k += 1;
                                break;
                            }
                        }
                        T::Str(s) => cur.push(s),
                        T::Id(_) => {}
                    }
                    k += 1;
                }
                cats.push(serde_json::json!({"id": cid, "name": name.take().unwrap_or_default(), "kinds": std::mem::take(&mut kinds), "entries": entries}));
            }
            _ => k += 1,
        }
    }
    from_value(&serde_json::json!({"categories": cats}))
}

fn from_value(v: &serde_json::Value) -> Result<Vec<Category>, String> {
    let list = v["categories"].as_array().ok_or("\"categories\" の配列がありません")?;
    let mut out: Vec<Category> = Vec::new();
    for (n, c) in list.iter().enumerate() {
        let id = c["id"].as_str().map(str::trim).filter(|s| !s.is_empty() && !s.contains(char::is_whitespace)).ok_or(format!("{}番目: id が不正です", n + 1))?;
        if out.iter().any(|x| x.id == id) {
            return Err(format!("{id}: idが重複しています"));
        }
        let name = c["name"].as_str().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(id);
        let raw = c["entries"].as_array().ok_or(format!("{id}: entries の配列がありません"))?;
        // 宣言された種類 (重複・空は除く)
        let mut kind_names: Vec<&str> = Vec::new();
        for kv in c["kinds"].as_array().into_iter().flatten() {
            let kname = kv.as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or(format!("{id}: kinds は文字列の配列にしてください"))?;
            if !kind_names.contains(&kname) {
                kind_names.push(kname);
            }
        }
        let declared = !kind_names.is_empty();
        let mut rows: Vec<(usize, Entry)> = Vec::new();
        for e in raw {
            let (Some(en), Some(ja)) = (e[0].as_str().map(str::trim), e[1].as_str().map(str::trim)) else {
                return Err(format!("{id}: entries は [\"english\", \"日本語\"] の組にしてください"));
            };
            if en.is_empty() || ja.is_empty() || en.contains(['\n', '\r']) || ja.contains(['\n', '\r']) {
                return Err(format!("{id}: 空の語や改行を含む語があります ({en})"));
            }
            // 3つ目は種類名。宣言が無ければ出てきた順に種類とする。宣言に無い名前は誤記なのでエラー
            let rank = match e.get(2).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
                Some(kn) => match kind_names.iter().position(|x| *x == kn) {
                    Some(i) => i,
                    None if declared => return Err(format!("{id}: 種類「{kn}」が kinds に宣言されていません ({en})")),
                    None => {
                        kind_names.push(kn);
                        kind_names.len() - 1
                    }
                },
                None => usize::MAX,
            };
            rows.push((rank, (leak(en), leak(ja))));
        }
        if rows.is_empty() {
            return Err(format!("{id}: entries が空です"));
        }
        // 種類を持たない語は、種類を使うカテゴリでは最後の「その他」にまとめる
        let mut kinds: Vec<(&'static str, usize)> = Vec::new();
        if !kind_names.is_empty() {
            if rows.iter().any(|(r, _)| *r == usize::MAX) {
                kind_names.push("その他");
            }
            let last = kind_names.len() - 1;
            for r in rows.iter_mut() {
                if r.0 == usize::MAX {
                    r.0 = last;
                }
            }
            rows.sort_by_key(|r| r.0); // 安定ソート: 種類の中では書いた順
            for (i, kn) in kind_names.iter().enumerate() {
                let n = rows.iter().filter(|r| r.0 == i).count();
                if n > 0 {
                    kinds.push((leak(kn), n));
                }
            }
        }
        let entries: Vec<Entry> = rows.into_iter().map(|(_, e)| e).collect();
        out.push(Category { id: leak(id), name: leak(name), entries: Box::leak(entries.into_boxed_slice()), kinds: Box::leak(kinds.into_boxed_slice()) });
    }
    if out.is_empty() {
        return Err("カテゴリがありません".into());
    }
    Ok(out)
}

pub fn category(id: &str) -> Option<&'static Category> {
    all().iter().find(|c| c.id == id)
}

/// 辞書から語を引く。日本語訳・英語プロンプトのどちらにも一致できる (英字は大文字小文字無視)。
/// `ids` のカテゴリを優先し、無ければ全カテゴリから探す。
pub fn lookup(ids: &[&str], text: &str) -> Option<&'static str> {
    // 完全一致を先に探し、無ければ語尾の「な・の」と空白・中黒を無視して探す (例: 色彩豊か = 色彩豊かな)
    let loose = |s: &str| -> String {
        let s: String = s.chars().filter(|c| !c.is_whitespace() && !matches!(c, '・' | '･')).collect();
        s.trim_end_matches(['な', 'の']).to_lowercase()
    };
    let want = loose(text);
    let exact = |c: &&Category| {
        c.entries
            .iter()
            .find(|(en, ja)| *ja == text || en.eq_ignore_ascii_case(text))
            .map(|(en, _)| *en)
    };
    let fuzzy = |c: &&Category| {
        c.entries
            .iter()
            .find(|(en, ja)| !want.is_empty() && (loose(ja) == want || loose(en) == want))
            .map(|(en, _)| *en)
    };
    let pri: Vec<&Category> = ids.iter().filter_map(|id| category(id)).collect();
    pri.iter()
        .find_map(|c| exact(c))
        .or_else(|| all().iter().find_map(|c| exact(&c)))
        .or_else(|| pri.iter().find_map(|c| fuzzy(c)))
        .or_else(|| all().iter().find_map(|c| fuzzy(&c)))
}

/// `lookup` で見つからない語を、辞書の日本語の連なりに分けて英語にする (例: カラー色彩 = color, colors)。
/// 全体を辞書の語だけで過不足なく分けられるときだけ成功し、語数が最も少ない分け方を使う。
pub fn lookup_compound(ids: &[&str], text: &str) -> Option<String> {
    if let Some(en) = lookup(ids, text) {
        return Some(en.to_string());
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 3 || chars.len() > 40 {
        return None;
    }
    // 日本語を含まない語は対象にしない
    if chars.iter().all(|c| c.is_ascii()) {
        return None;
    }
    let pri: Vec<&Category> = ids.iter().filter_map(|id| category(id)).collect();
    let pieces = |start: usize| -> Vec<(usize, &'static str)> {
        let rest: String = chars[start..].iter().collect();
        let mut out: Vec<(usize, &'static str)> = Vec::new();
        for c in pri.iter().copied().chain(all().iter()) {
            for (en, ja) in c.entries {
                let n = ja.chars().count();
                if n >= 2 && rest.starts_with(ja) && !out.iter().any(|(l, e)| *l == n && e == en) {
                    out.push((n, en));
                }
            }
        }
        out
    };
    // best[i] = 先頭 i 文字を分ける最小の語数と、その英語の並び
    let mut best: Vec<Option<(usize, Vec<&'static str>)>> = vec![None; chars.len() + 1];
    best[0] = Some((0, Vec::new()));
    for i in 0..chars.len() {
        let Some((cnt, words)) = best[i].clone() else { continue };
        for (n, en) in pieces(i) {
            let j = i + n;
            if best[j].as_ref().is_none_or(|(c, _)| cnt + 1 < *c) {
                let mut w = words.clone();
                w.push(en);
                best[j] = Some((cnt + 1, w));
            }
        }
    }
    best[chars.len()].take().map(|(_, w)| w.join(", "))
}
