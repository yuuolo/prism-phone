use prism_android::document::Document;

fn document(source: &str, script: &str) -> Document {
    Document {
        version: 1,
        name: "测试配置".into(),
        source: source.into(),
        script: script.into(),
    }
}

#[test]
fn overwrite_retains_full_document_and_builds_multiple_groups() {
    let source = r#"
proxies:
  - {name: edge, type: socks5, server: example.com, port: 1080}
proxy-groups:
  - {name: automatic, type: url-test, proxies: [edge]}
  - {name: select, type: select, proxies: [automatic, DIRECT]}
rules: ['MATCH,select']
dns: {enable: true, nameserver: ['https://dns.example/dns-query']}
x-private-extension: {preserved: true}
"#;
    let doc = document(
        source,
        r#"function main(c) {
        c['proxy-groups'].push({name:'backup', type:'fallback', proxies:['edge']});
        c.rules.unshift('DOMAIN-SUFFIX,example.org,backup');
        return c;
    }"#,
    );
    let result = doc.preview().unwrap();
    assert_eq!(result.profile.proxies.len(), 1);
    assert_eq!(result.profile.groups.len(), 3);
    assert_eq!(result.profile.rules.len(), 2);
    assert_eq!(
        result.profile.groups[0].url,
        prism_core::config::DEFAULT_TEST_URL
    );
    assert_eq!(
        result.profile.dns.nameserver,
        ["https://dns.example/dns-query"]
    );
    let json: serde_json::Value = serde_json::from_str(&result.json).unwrap();
    assert_eq!(json["x-private-extension"]["preserved"], true);
    assert_eq!(doc.source, source);
    assert_eq!(doc.preview().unwrap().json, result.json);
}

#[test]
fn broken_references_and_cycles_are_not_sanitized_to_direct() {
    for source in [
        "proxy-groups: [{name: a, type: select, proxies: [missing]}]",
        "proxy-groups: [{name: a, type: select, proxies: []}]",
        "proxy-groups: [{name: a, type: select, proxies: [a]}]",
        "proxy-groups: [{name: a, type: select, proxies: [b]}, {name: b, type: select, proxies: [a]}]",
        "proxy-groups: [{name: a, type: select, use: [missing]}]",
        "rules: ['MATCH,missing']",
        "rules: ['RULE-SET,missing,DIRECT']",
        "proxies: [{name: DIRECT, type: socks5, server: example.com, port: 1080}]",
        "proxy-groups: [{name: a, type: select, proxies: [DIRECT]}, {name: a, type: select, proxies: [DIRECT]}]",
    ] {
        assert!(document(source, "").preview().is_err(), "{source}");
    }
}

#[test]
fn malformed_entries_and_parser_downgrades_are_rejected() {
    for source in [
        "proxies: [null]",
        "proxy-groups: [{name: a, type: unknown, proxies: [DIRECT]}]",
        "proxy-groups: [{name: a, type: select, proxies: [12]}]",
        "rules: [null]",
        "proxy-providers: {source: null}",
        "proxies: [{name: secret, type: unsupported}]",
        "outbounds: [{type: direct, tag: direct}]",
    ] {
        assert!(document(source, "").preview().is_err(), "{source}");
    }
    let original = document(
        "rules: ['MATCH,DIRECT']",
        "function main(c) { c.rules=['MATCH,missing']; return c; }",
    );
    assert!(original.preview().is_err());
    assert_eq!(original.source, "rules: ['MATCH,DIRECT']");
}

#[test]
fn provider_references_are_preserved_for_later_resolution() {
    let result = document(
        r#"
proxy-providers:
  subscription: {type: http, url: 'https://example.com/nodes.yaml'}
rule-providers:
  ads: {type: http, behavior: domain, url: 'https://example.com/ads.yaml'}
proxy-groups:
  - {name: automatic, type: url-test, use: [subscription]}
rules: ['RULE-SET,ads,REJECT', 'MATCH,automatic']
"#,
        "",
    )
    .preview()
    .unwrap();
    assert_eq!(result.profile.groups[0].use_providers, ["subscription"]);
    assert!(result.profile.groups[0].proxies.is_empty());
    assert_eq!(result.profile.rule_providers.len(), 1);
    assert_eq!(result.profile.rules.len(), 2);
}
