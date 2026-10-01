use super::support::fixture;

#[test]
fn readiness_is_metadata_only_and_never_exposes_authority_material() {
    let fixture = fixture();
    let readiness = fixture.console.readiness();
    let value = serde_json::to_string(&readiness).expect("JSON");
    assert!(value.contains("\"state\":\"unavailable\""));
    assert!(!readiness.checks.management_lifeline_verified);
    assert!(!readiness.checks.normal_boundary_separated);
    assert!(!readiness.checks.two_person_recovery);
    for forbidden in [
        "public_key",
        "subject_id",
        "signature",
        "capability",
        "secret",
    ] {
        assert!(!value.contains(forbidden));
    }
}
