use mpc_api::security::*;

#[test]
fn test_security_policy_creation() {
    let policy = SecurityPolicy::high();
    assert_eq!(policy.security_level, SecurityLevel::High);
    assert!(policy.enable_threat_detection);
    assert!(policy.enable_audit_logging);
}

#[test]
fn test_security_event_creation() {
    let event = SecurityEvent::new(
        ThreatType::TimingAttack,
        SecurityLevel::Medium,
        "测试事件".to_string(),
    );
    assert_eq!(event.threat_type, ThreatType::TimingAttack);
    assert_eq!(event.severity, SecurityLevel::Medium);
    assert!(!event.is_handled);
}

#[test]
fn test_threat_detector() {
    let policy = SecurityPolicy::medium();
    let detector = ThreatDetector::new(policy);
    
    let result = detector.report_anomaly("测试异常");
    assert!(result.is_ok());
}

#[test]
fn test_audit_logger() {
    let policy = SecurityPolicy::medium();
    let logger = AuditLogger::new(policy);
    
    let event = SecurityEvent::new(
        ThreatType::ProtocolAttack,
        SecurityLevel::Low,
        "测试日志".to_string(),
    );
    
    let result = logger.log_event(event);
    assert!(result.is_ok());
    
    let events = logger.get_events();
    assert!(!events.is_empty());
}

#[test]
fn test_security_manager() {
    let mgr = SecurityManager::with_policy(SecurityPolicy::low()).unwrap();
    let result = mgr.start();
    assert!(result.is_ok());
    
    mgr.stop();
}