use serde_json::json;

fn main() {
    let command = std::env::args().nth(1);
    if command.as_deref() != Some("sample-readiness") {
        eprintln!("usage: crowsi-rescue-console sample-readiness");
        std::process::exit(64);
    }
    let value = json!({
        "schema": "crowsi://rescue/deployment-readiness/v1",
        "state": "unavailable",
        "external_actions": false,
        "reason_codes": [
            "out-of-band-lifeline-not-provisioned",
            "rescue-os-identity-not-provisioned",
            "recovery-authorities-not-enrolled",
            "recovery-drill-not-verified"
        ],
        "checks": {
            "lifeline": false,
            "rescue_identity": false,
            "recovery_authorities": false,
            "two_person_recovery": false,
            "drill_evidence": false
        }
    });
    match serde_json::to_string(&value) {
        Ok(encoded) => println!("{encoded}"),
        Err(_) => std::process::exit(70),
    }
}
