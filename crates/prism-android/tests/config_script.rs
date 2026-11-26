use prism_android::script::{self, Failure};
use serde_json::json;
use std::time::{Duration, Instant};

#[test]
fn clash_main_mutates_groups_rules_and_dns_without_changing_input() {
    let input = json!({"proxies":[],"proxy-groups":[],"rules":["MATCH,DIRECT"]}).to_string();
    let original = input.clone();
    let name = "name'); throw new Error('injection') //";
    let output = script::apply(
        &input,
        r#"function main(config, profileName) {
        const group = {name: profileName, type: 'select', proxies: ['DIRECT','REJECT']};
        config['proxy-groups'].push(group);
        config.rules.unshift('DOMAIN-SUFFIX,ads.test,REJECT');
        config.dns = {enable: true, hosts: {'local.test':'127.0.0.1'}};
        return config;
    }"#,
        name,
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["proxy-groups"][0]["name"], name);
    assert_eq!(parsed["rules"][0], "DOMAIN-SUFFIX,ads.test,REJECT");
    assert_eq!(parsed["dns"]["hosts"]["local.test"], "127.0.0.1");
    assert_eq!(input, original);
}

#[test]
fn host_io_and_shared_memory_blocking_are_not_available() {
    script::apply("{}",r#"function main(c) {
        for(const key of ['process','require','std','os','fetch','XMLHttpRequest','WebSocket','Worker','Atomics','SharedArrayBuffer'])
            if(typeof globalThis[key] !== 'undefined') throw new Error('unexpected host API');
        return c;
    }"#,"test").unwrap();
}

#[test]
fn infinite_loop_is_interrupted_even_inside_catch_and_next_call_recovers() {
    let start = Instant::now();
    assert_eq!(
        script::apply(
            "{}",
            "function main(c){while(true){try{while(true){}}catch(e){}}}",
            "test"
        ),
        Err(Failure::Timeout)
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(
        script::apply("{}", "function main(c){c.ok=true;return c;}", "test").unwrap(),
        "{\"ok\":true}"
    );
}

#[test]
fn memory_and_stack_exhaustion_fail_without_returning_a_replacement() {
    assert!(script::apply(
        "{}",
        "function main(c){c.x=new ArrayBuffer(512*1024*1024);return c;}",
        "test"
    )
    .is_err());
    assert!(script::apply("{}", "function main(c){return main(c);}", "test").is_err());
    assert_eq!(
        script::apply("{}", "function main(c){return c;}", "test").unwrap(),
        "{}"
    );
}

#[test]
fn async_non_object_and_circular_results_are_rejected() {
    for source in [
        "function main(c){return null;}",
        "function main(c){return [];}",
        "function main(c){}",
        "async function main(c){return c;}",
        "function main(c){c.self=c;return c;}",
    ] {
        assert!(script::apply("{}", source, "test").is_err());
    }
}

#[test]
fn source_input_output_bounds_and_sanitized_errors_are_enforced() {
    assert_eq!(
        script::apply("[]", "function main(c){return c;}", "test"),
        Err(Failure::Input)
    );
    assert_eq!(
        script::apply("{}", &" ".repeat(script::MAX_SCRIPT + 1), "test"),
        Err(Failure::Limit)
    );
    assert_eq!(
        script::apply(&" ".repeat(script::MAX_CONFIG + 1), "", "test"),
        Err(Failure::Limit)
    );
    assert!(script::apply(
        "{}",
        "function main(c){c.x='x'.repeat(5*1024*1024);return c;}",
        "test"
    )
    .is_err());
    let failure = script::apply(
        "{}",
        "function main(c){throw new Error('private-node-secret');}",
        "test",
    )
    .unwrap_err();
    assert!(!failure.to_string().contains("private-node-secret"));
}
