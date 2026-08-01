//! The zh-TW locale pack's public behaviour, and the two things it must not
//! break (AAASM-5353).
//!
//! Driven through the crate's public API only, so it also proves the pack is
//! reachable from outside `aa-security` — the SDK and WASM layers reach it the
//! same way.

use aa_security::canonical::redact_findings;
use aa_security::locale::zh_tw;
use aa_security::CredentialScanner;

/// Clean Traditional-Chinese technical prose, carrying the numeric content real
/// documents carry: dates, versions, ports, counts, monetary amounts and
/// timestamps.
///
/// The numbers are the point. A corpus of pure Han text would pass this test
/// even if every recognizer matched any digit run, so the assertion would prove
/// nothing — and this programme has already shipped clean-prose vectors whose
/// text could not reach the code they were meant to exercise. The assertions
/// below therefore check the corpus is numerically dense *before* checking it is
/// clean.
const CLEAN_ZH_TW_PROSE: &str = "\
代理程式在執行工具前，必須先向政策引擎詢問決策。若政策拒絕，該次呼叫不會發生，稽核記錄仍會保留完整原因。
本文件對應版本 v0.0.1-rc.7，最後更新於 2026-08-01，前一版是 2026-07-24 發布的 rc.6。
閘道器預設監聽 50051 埠，儀表板使用 3000 埠，代理程式的側車代理則使用 8080 埠。
第一季共處理 1,250,000 次決策請求，其中 3,412 次被拒絕，佔比約 0.27%，較上一季下降 12 個百分點。
政策評估的第 95 百分位延遲為 1.8 毫秒，第 99 百分位為 4.6 毫秒，皆低於 10 毫秒的服務水準目標。
稽核事件的保留期限為 365 天，超過後由背景工作批次清除，每次批次最多處理 5000 筆。
系統於 2026-08-01T09:15:30Z 完成一次滾動升級，共重啟 24 個執行個體，耗時 7 分 42 秒。
團隊每月預算上限為 500 美元，目前已使用 312.75 美元，剩餘額度會在下個月 1 日重置。
共有 18 條規則生效，其中 6 條屬於網路出口限制，9 條屬於工具呼叫限制，3 條屬於資料外洩防護。
若需要調整設定，請參閱第 4 章第 2 節，該節說明了三層攔截模型的部署順序與各層的延遲成本。
核心程式庫以 Rust 1.75 以上版本編譯，語言軟體開發套件分別支援 Python 3.12、Node 22 與 Go 1.23。
本次審查共發現 7 項待辦事項，預計於 2026 年第三季完成，屆時會再安排一次完整的回歸測試。
訂單編號 2026070912 已於 2026-07-09 出貨，物流單號為 9527001234，預計 3 個工作天內送達。
會議記錄編號 20260715，與會者 12 人，議程共 5 項，會議自 14:30 進行至 16:05 結束。
資料庫連線集區大小設為 10，逾時時間 30 秒，重試次數 3 次，退避間隔為 250 毫秒起算。
發票金額合計 48,300 元，含稅 5%，折讓 1,200 元，實收 47,100 元，付款期限為 30 日內。
本季共新增 47 個代理程式、9 個團隊與 214 條稽核規則，其中 128 條沿用自上一季的設定。
效能測試在 4 核心 16 GB 記憶體的機器上執行，並行度為 64，總共送出 100000 次請求。
文件第 7 版於 2026-06-30 定稿，第 8 版預計 2026-09-15 發布，兩版之間差異約 320 行。
錯誤代碼 4001 表示政策不存在，4003 表示權限不足，5002 表示後端逾時，請依代碼分別處理。";

/// A high-entropy ASCII secret used to prove the locale pack did not weaken the
/// existing detectors. Not a real credential — a fixed alphanumeric run.
const ASCII_SECRET: &str = "ghp_0123456789abcdefABCDEF0123456789abcd";

/// Ordinary zh-TW prose must produce no findings — from either scanner.
///
/// This is the defect the whole Epic exists to fix: 32 KB of clean Traditional
/// Chinese previously produced 87 findings, because the entropy gate scored
/// UTF-8 bytes against a threshold calibrated on English characters. AAASM-5344
/// fixed that; this ticket must not undo it by adding recognizers loose enough
/// to reintroduce it from the other direction.
#[test]
fn clean_zh_tw_prose_produces_no_findings_from_either_scanner() {
    // Non-vacuity first. A corpus that cannot reach the recognizers would make
    // the assertions below pass for the wrong reason.
    let digits = CLEAN_ZH_TW_PROSE.chars().filter(char::is_ascii_digit).count();
    assert!(
        CLEAN_ZH_TW_PROSE.len() > 2000,
        "corpus is too small to be evidence: {} bytes",
        CLEAN_ZH_TW_PROSE.len()
    );
    assert!(
        digits > 150,
        "corpus has too few digits to exercise the digit recognizers: {digits}"
    );

    let scanner_findings = CredentialScanner::new().scan(CLEAN_ZH_TW_PROSE).findings;
    assert!(
        scanner_findings.is_empty(),
        "clean zh-TW prose produced {} credential findings: {:?}",
        scanner_findings.len(),
        scanner_findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );

    let locale_findings = zh_tw::scan(CLEAN_ZH_TW_PROSE);
    assert!(
        locale_findings.is_empty(),
        "clean zh-TW prose produced {} locale findings: {:?}",
        locale_findings.len(),
        locale_findings
            .iter()
            .map(|f| {
                let s = f.span();
                (f.category().to_string(), &CLEAN_ZH_TW_PROSE[s.start()..s.end()])
            })
            .collect::<Vec<_>>()
    );

    // And redaction over an empty finding set returns the text, not a blank.
    assert_eq!(redact_findings(CLEAN_ZH_TW_PROSE, &locale_findings), CLEAN_ZH_TW_PROSE);
}

/// The standing D-3 constraint: nothing in this ticket may weaken detection of
/// ASCII base64, hex or high-entropy secrets.
///
/// The locale pack is a separate entry point and does not touch
/// `CredentialScanner`, so this holds structurally — but "holds structurally"
/// is what every regression looked like beforehand. Asserted against the same
/// text the locale pack is scanning, so a future change that *did* wire the two
/// together cannot quietly trade one for the other.
#[test]
fn ascii_secret_detection_survives_beside_the_locale_pack() {
    let payload = format!("{CLEAN_ZH_TW_PROSE}\n授權標頭：{ASCII_SECRET}\n");

    let result = CredentialScanner::new().scan(&payload);
    // Raw-secret absence, not finding count: a 40-character `ghp_` token trips
    // both the literal detector and the base64-run backstop, and that overlap
    // is long-standing scanner behaviour rather than anything this ticket
    // changes. What must hold is that the secret is identified and removed.
    assert!(
        result.findings.iter().any(|f| f.kind.as_str() == "GitHubPat"),
        "the ASCII secret must still be identified as a GitHub PAT, got {:?}",
        result.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
    assert!(
        !result.redact(&payload).contains(ASCII_SECRET),
        "the ASCII secret survived redaction"
    );
    // And the surrounding prose still contributes nothing of its own.
    assert!(
        result.findings.iter().all(|f| f.offset >= CLEAN_ZH_TW_PROSE.len()),
        "a finding landed inside the clean prose"
    );
}

/// A payload carrying both an ASCII secret and a Taiwanese identifier must lose
/// both, each through its own scanner.
///
/// The two findings sets are disjoint in category and are produced by different
/// recognizers, so a caller has to run both and combine them. This is what that
/// looks like end to end, and it is the shape AAASM-5355's ingest path will use.
#[test]
fn a_mixed_payload_loses_both_the_ascii_secret_and_the_taiwanese_identifier() {
    // `A200000003`: letter A → area code 10, so n₁·1 + n₂·9 = 1; the body
    // `20000000` contributes 2 × 8 = 16; the check digit 3 brings the weighted
    // sum to 20, which is divisible by 10. Constructed, not observed.
    let identifier = "A200000003";
    // A space after the secret, because the scanner's literal detector extends
    // a finding to the end of its whitespace token — punctuation glued to the
    // token is swallowed into the span. That is existing, tested behaviour and
    // not this ticket's to change; the payload is written so the exact-string
    // assertion below is about the locale pack rather than about that.
    let payload = format!("身分證字號 {identifier}，授權標頭 {ASCII_SECRET} ，請儘速處理。");

    let scanner_redacted = CredentialScanner::new().scan(&payload).redact(&payload);
    assert!(!scanner_redacted.contains(ASCII_SECRET), "ASCII secret survived");

    let locale_findings = zh_tw::scan(&scanner_redacted);
    assert_eq!(locale_findings.len(), 1, "the identifier must be found");
    assert_eq!(
        locale_findings[0].category().to_string(),
        "NATIONAL_ID[zh-TW/national_id]"
    );

    let fully_redacted = redact_findings(&scanner_redacted, &locale_findings);
    assert!(!fully_redacted.contains(identifier), "identifier survived redaction");
    assert!(!fully_redacted.contains(ASCII_SECRET), "ASCII secret reappeared");
    assert_eq!(
        fully_redacted,
        "身分證字號 [REDACTED]，授權標頭 [REDACTED:GitHubPat] ，請儘速處理。"
    );
}
