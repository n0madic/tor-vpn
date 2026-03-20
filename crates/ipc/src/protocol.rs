use serde::{Deserialize, Serialize};

/// IPC request from a client (CLI or UI) to the running daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum Request {
    /// Query current VPN status (live data from daemon memory).
    Status,
    /// Refresh Tor circuits (invalidate isolation caches + DNS cache).
    Refresh,
    /// Gracefully shut down the daemon.
    Shutdown,
}

/// IPC response from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Response {
    /// Status response with live VPN state.
    Status {
        state: Box<state::VpnState>,
        uptime_secs: u64,
    },
    /// Success response.
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Error response.
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_status_serialization() {
        let req = Request::Status;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"command":"status"}"#);
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Status));
    }

    #[test]
    fn test_request_refresh_serialization() {
        let req = Request::Refresh;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"command":"refresh"}"#);
    }

    #[test]
    fn test_request_shutdown_serialization() {
        let req = Request::Shutdown;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"command":"shutdown"}"#);
    }

    #[test]
    fn test_response_ok_with_message() {
        let resp = Response::Ok {
            message: Some("done".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""type":"ok""#));
        assert!(json.contains(r#""message":"done""#));
    }

    #[test]
    fn test_response_ok_without_message() {
        let resp = Response::Ok { message: None };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_response_error() {
        let resp = Response::Error {
            message: "bad request".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""type":"error""#));
        assert!(json.contains("bad request"));
    }

    #[test]
    fn test_response_status_with_vpn_state() {
        let state = state::VpnState {
            pid: 1234,
            tun_name: "utun7".into(),
            original_gateway: "192.168.1.1".into(),
            original_interface: "en0".into(),
            guard_ips: vec!["1.2.3.4".parse().unwrap()],
            bypass_cidrs: vec![],
            dns_service_name: None,
            original_dns: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            tx_bytes: 1024,
            rx_bytes: 2048,
            started_at: 0,
        };
        let resp = Response::Status {
            state: Box::new(state),
            uptime_secs: 300,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""type":"status""#));
        assert!(json.contains(r#""pid":1234"#));
        assert!(json.contains(r#""uptime_secs":300"#));

        let parsed: Response = serde_json::from_str(&json).unwrap();
        match parsed {
            Response::Status { state, uptime_secs } => {
                assert_eq!(state.pid, 1234);
                assert_eq!(uptime_secs, 300);
            }
            _ => panic!("expected Status response"),
        }
    }

    #[test]
    fn test_request_unknown_command_rejected() {
        let result: Result<Request, _> = serde_json::from_str(r#"{"command":"unknown"}"#);
        assert!(result.is_err());
    }
}
