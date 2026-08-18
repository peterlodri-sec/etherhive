use etherhive::irc::{IrcDaemon, Message};
use etherhive::crypto::{DisplayName, Identity};

#[test]
fn test_call_signaling_messages() {
    let mut daemon = IrcDaemon::new(Identity {
        route_id: "caller_node".into(),
        display_name: DisplayName { raw: "alice".into(), ascii_prefix: "alice".into() },
        vector_hash: "012345".into(),
    });

    let offer = Message::CallOffer {
        from: "alice.eth".into(),
        to: "bob.eth".into(),
        call_id: "call-1234".into(),
        sdp: "v=0\r\nm=audio 5004 RTP/SAVPF 111\r\n".into(),
    };

    let _answer = Message::CallAnswer {
        from: "bob.eth".into(),
        to: "alice.eth".into(),
        call_id: "call-1234".into(),
        sdp: "v=0\r\nm=audio 5004 RTP/SAVPF 111\r\n".into(),
    };

    let _hangup = Message::CallHangup {
        from: "alice.eth".into(),
        to: "bob.eth".into(),
        call_id: "call-1234".into(),
        reason: Some("completed".into()),
    };

    let bridge = Message::CallBridge {
        target: "bob.eth".into(),
        sip_uri: "sip:bob.eth@arnacon.net".into(),
        x_data: "550e8400-e29b-41d4-a716-446655440000:1640995200".into(),
        x_sign: "0x1234".into(),
    };

    // Serialize & deserialize test
    let serialized_offer = serde_json::to_string(&offer).expect("serialize offer");
    let deserialized_offer: Message = serde_json::from_str(&serialized_offer).expect("deserialize offer");
    assert!(matches!(deserialized_offer, Message::CallOffer { .. }));

    let serialized_bridge = serde_json::to_string(&bridge).expect("serialize bridge");
    let deserialized_bridge: Message = serde_json::from_str(&serialized_bridge).expect("deserialize bridge");
    assert!(matches!(deserialized_bridge, Message::CallBridge { .. }));

    // Daemon handles ping pong without panic
    let pong = daemon.handle(Message::Ping);
    assert!(matches!(pong, Some(Message::Pong)));
}
