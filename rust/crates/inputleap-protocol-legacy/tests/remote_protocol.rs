use inputleap_protocol_legacy::{
    ByteCursor, Category, ClientSession, ClientSessionEvent, ClientSessionState, ExpectedHandshake,
    FrameParseResult, Handshake, LengthPrefixedBytes, MAX_PAYLOAD_LENGTH, MAX_STRING_LENGTH,
    REMOTE_MESSAGE_CODE_LENGTH, RemoteEncodeError, RemoteEncodeToError, RemoteMessage,
    RemoteMessageContext, RemoteMessageDirection, RemoteMessageState, ServerSession,
    ServerSessionEvent, ServerSessionState, encode_remote_message, encode_remote_message_to,
    parse_handshake, parse_remote_frame, parse_remote_message,
};

const WRITEF_CONSECUTIVE_STRINGS: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/writef-consecutive-strings.bin");
const REMOTE_HELLO_1_6: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/remote-hello-1-6.bin");
const REMOTE_HELLO_BACK_1_7: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/remote-hello-back-1-7.bin");
const REMOTE_TRUNCATED_PREFIX: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/remote-truncated-prefix.bin");
const REMOTE_OVERSIZED_LENGTH: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/remote-oversized-length.bin");
const REMOTE_UNKNOWN_CODE: &[u8] =
    include_bytes!("../../../../src/test/fixtures/rust-r0-wire/remote-unknown-code.bin");
const REMOTE_ZERO_LENGTH: &[u8] = include_bytes!("fixtures/remote-zero-length.bin");
const REMOTE_CNOP_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-cnop-payload.bin");
const REMOTE_QINF_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-qinf-payload.bin");
const REMOTE_CIAK_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-ciak-payload.bin");
const REMOTE_CROP_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-crop-payload.bin");
const REMOTE_COUT_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-cout-payload.bin");
const REMOTE_CBYE_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-cbye-payload.bin");
const REMOTE_EBSY_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-ebsy-payload.bin");
const REMOTE_EUNK_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-eunk-payload.bin");
const REMOTE_EBAD_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-ebad-payload.bin");
const REMOTE_CALV_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-calv-payload.bin");
const REMOTE_EICV_1_6_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-eicv-1-6-payload.bin");
const REMOTE_CSEC_OFF_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-csec-off-payload.bin");
const REMOTE_CSEC_ON_PAYLOAD: &[u8] = include_bytes!("fixtures/remote-csec-on-payload.bin");
const REMOTE_DMDN_BUTTON1_PAYLOAD: &[u8] =
    include_bytes!("fixtures/remote-dmdn-button1-payload.bin");
const REMOTE_DMUP_BUTTON1_PAYLOAD: &[u8] =
    include_bytes!("fixtures/remote-dmup-button1-payload.bin");
const REMOTE_DKDN_BOUNDARY_FRAME: &[u8] = include_bytes!("fixtures/remote-dkdn-boundary-frame.bin");
const REMOTE_DKRP_BOUNDARY_FRAME: &[u8] = include_bytes!("fixtures/remote-dkrp-boundary-frame.bin");
const REMOTE_DKUP_BOUNDARY_FRAME: &[u8] = include_bytes!("fixtures/remote-dkup-boundary-frame.bin");

const ALL_REMOTE_MESSAGE_CONTEXTS: [RemoteMessageContext; 8] = [
    RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::ClientHandshake,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::ServerAwaitingHelloBack,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::ServerAwaitingInfo,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::ClientHandshake,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::ServerAwaitingHelloBack,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::ServerAwaitingInfo,
    ),
    RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::Active,
    ),
];

const CLIENT_HANDSHAKE: RemoteMessageContext = RemoteMessageContext::new(
    RemoteMessageDirection::ServerToClient,
    RemoteMessageState::ClientHandshake,
);
const CLIENT_ACTIVE: RemoteMessageContext = RemoteMessageContext::new(
    RemoteMessageDirection::ServerToClient,
    RemoteMessageState::Active,
);

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

fn hello_payload(version: (i16, i16)) -> Vec<u8> {
    let mut payload = b"Barrier".to_vec();
    payload.extend_from_slice(&version.0.to_be_bytes());
    payload.extend_from_slice(&version.1.to_be_bytes());
    payload
}

fn hello_back_payload(version: (i16, i16), declared_name_len: u32, name: &[u8]) -> Vec<u8> {
    let mut payload = hello_payload(version);
    payload.extend_from_slice(&declared_name_len.to_be_bytes());
    payload.extend_from_slice(name);
    payload
}

fn accepted_payload(frame: &[u8]) -> &[u8] {
    match parse_remote_frame(frame) {
        FrameParseResult::Accepted { consumed, payload } => {
            assert_eq!(consumed, frame.len());
            payload
        }
        result => panic!("expected accepted frame, got {result:?}"),
    }
}

#[test]
fn frozen_hello_1_6_is_framed_then_accepted_in_hello_state() {
    let payload = accepted_payload(REMOTE_HELLO_1_6);
    let parsed = parse_handshake(payload, ExpectedHandshake::Hello);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(11));
    assert_eq!(
        parsed.handshake,
        Some(Handshake::Hello { major: 1, minor: 6 })
    );
}

#[test]
fn hello_versions_follow_the_cpp_client_negotiation_rule() {
    for version in [(1, 6), (1, 7), (2, 0), (2, -1), (i16::MAX, i16::MIN)] {
        let payload = hello_payload(version);
        assert_eq!(
            parse_handshake(&payload, ExpectedHandshake::Hello).category,
            Category::Accepted
        );
    }

    for version in [(1, 5), (0, 99), (-1, 6), (i16::MIN, i16::MIN)] {
        let payload = hello_payload(version);
        let parsed = parse_handshake(&payload, ExpectedHandshake::Hello);
        assert_eq!(parsed.category, Category::UnsupportedVersion);
        assert_eq!(parsed.consumed, Some(11));
    }
}

#[test]
fn decoded_versions_preserve_the_cpp_signed_i16_type() {
    let payload = hello_payload((-1, i16::MIN));
    let parsed = parse_handshake(&payload, ExpectedHandshake::Hello);

    assert_eq!(parsed.category, Category::UnsupportedVersion);
    let frozen = parse_handshake(accepted_payload(REMOTE_HELLO_1_6), ExpectedHandshake::Hello);
    let Some(Handshake::Hello { major, minor }) = frozen.handshake else {
        panic!("expected accepted hello");
    };
    let _: i16 = major;
    let _: i16 = minor;
}

#[test]
fn frozen_hello_back_1_7_is_framed_then_unsupported_in_hello_back_state() {
    let payload = accepted_payload(REMOTE_HELLO_BACK_1_7);
    let parsed = parse_handshake(payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::UnsupportedVersion);
    assert_eq!(parsed.consumed, Some(payload.len()));
    assert_eq!(parsed.handshake, None);
}

#[test]
fn version_1_7_is_directional_between_hello_and_hello_back() {
    let hello = hello_payload((1, 7));
    let hello_back = hello_back_payload((1, 7), 0, b"");

    assert_eq!(
        parse_handshake(&hello, ExpectedHandshake::Hello).category,
        Category::Accepted
    );
    assert_eq!(
        parse_handshake(&hello_back, ExpectedHandshake::HelloBack).category,
        Category::UnsupportedVersion
    );
}

#[test]
fn frozen_truncated_prefix_needs_more_without_consuming() {
    let parsed = parse_remote_frame(REMOTE_TRUNCATED_PREFIX);

    assert_eq!(parsed, FrameParseResult::NeedMore);
}

#[test]
fn frozen_oversized_length_is_rejected_from_prefix() {
    let parsed = parse_remote_frame(REMOTE_OVERSIZED_LENGTH);

    assert_eq!(parsed, FrameParseResult::Oversized);
}

#[test]
fn frozen_unknown_code_is_accepted_by_framing_then_malformed_by_handshake() {
    let payload = accepted_payload(REMOTE_UNKNOWN_CODE);
    assert_eq!(payload, b"ZZZZ");

    let parsed = parse_handshake(payload, ExpectedHandshake::Hello);
    assert_eq!(parsed.category, Category::Malformed);
    assert_eq!(parsed.consumed, None);
    assert_eq!(parsed.handshake, None);
}

#[test]
fn cursor_reads_frozen_consecutive_writef_strings_without_allocation() {
    assert_eq!(&WRITEF_CONSECUTIVE_STRINGS[..4], b"TEST");
    let mut cursor = ByteCursor::new(&WRITEF_CONSECUTIVE_STRINGS[4..]);

    assert_eq!(
        cursor.read_u32_length_prefixed(MAX_STRING_LENGTH),
        LengthPrefixedBytes::Complete(b"alpha")
    );
    assert_eq!(
        cursor.read_u32_length_prefixed(MAX_STRING_LENGTH),
        LengthPrefixedBytes::Complete(b"beta")
    );
    assert_eq!(cursor.remaining(), 0);
}

#[test]
fn partial_payload_after_complete_prefix_needs_more_without_consuming() {
    let parsed = parse_remote_frame(&REMOTE_HELLO_1_6[..REMOTE_HELLO_1_6.len() - 1]);

    assert_eq!(parsed, FrameParseResult::NeedMore);
}

#[test]
fn partial_name_inside_complete_frame_is_malformed_by_handshake_only() {
    let framed = frame(&hello_back_payload((1, 6), 4, b"abc"));
    let payload = accepted_payload(&framed);
    let parsed = parse_handshake(payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Malformed);
    assert_eq!(parsed.consumed, None);
}

#[test]
fn name_over_one_mib_is_oversized_before_name_bytes_are_read() {
    let framed = frame(&hello_back_payload(
        (1, 6),
        u32::try_from(MAX_STRING_LENGTH + 1).unwrap(),
        &[],
    ));
    let payload = accepted_payload(&framed);
    let parsed = parse_handshake(payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Oversized);
    assert_eq!(parsed.consumed, None);
}

#[test]
fn hello_preserves_a_following_command_in_the_same_payload() {
    let mut payload = hello_payload((1, 6));
    payload.extend_from_slice(b"CNOP");

    let parsed = parse_handshake(&payload, ExpectedHandshake::Hello);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(11));
    assert_eq!(&payload[parsed.consumed.unwrap()..], b"CNOP");
}

#[test]
fn hello_back_preserves_trailing_bytes_for_the_caller() {
    let mut payload = hello_back_payload((1, 6), 3, b"abc");
    payload.extend_from_slice(b"CNOP");

    let parsed = parse_handshake(&payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(18));
    assert_eq!(&payload[parsed.consumed.unwrap()..], b"CNOP");
    assert_eq!(
        parsed.handshake,
        Some(Handshake::HelloBack {
            major: 1,
            minor: 6,
            client_name: b"abc",
        })
    );
}

#[test]
fn hello_back_of_exactly_1024_bytes_is_accepted() {
    let name = vec![b'n'; 1009];
    let payload = hello_back_payload((1, 6), 1009, &name);
    assert_eq!(payload.len(), 1024);

    let parsed = parse_handshake(&payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(1024));
}

#[test]
fn hello_back_of_1025_bytes_is_malformed() {
    let name = vec![b'n'; 1010];
    let payload = hello_back_payload((1, 6), 1010, &name);
    assert_eq!(payload.len(), 1025);

    let parsed = parse_handshake(&payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Malformed);
    assert_eq!(parsed.consumed, None);
}

#[test]
fn hello_back_payload_over_1024_is_malformed_even_when_the_greeting_is_exactly_1024() {
    let name = vec![b'n'; 1009];
    let mut payload = hello_back_payload((1, 6), 1009, &name);
    payload.extend_from_slice(b"X");

    let parsed = parse_handshake(&payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Malformed);
    assert_eq!(parsed.consumed, None);
}

#[test]
fn coalesced_outer_frames_consume_only_the_first_frame() {
    let mut coalesced = REMOTE_HELLO_1_6.to_vec();
    coalesced.extend_from_slice(REMOTE_UNKNOWN_CODE);

    let parsed = parse_remote_frame(&coalesced);

    assert_eq!(
        parsed,
        FrameParseResult::Accepted {
            consumed: REMOTE_HELLO_1_6.len(),
            payload: &REMOTE_HELLO_1_6[4..],
        }
    );
}

#[test]
fn zero_length_prefix_is_skipped_without_producing_a_frame_or_error() {
    let parsed = parse_remote_frame(REMOTE_ZERO_LENGTH);

    assert_eq!(
        parsed,
        FrameParseResult::SkippedEmpty {
            consumed: REMOTE_ZERO_LENGTH.len(),
        }
    );
}

#[test]
fn exact_maximum_frame_payload_is_accepted() {
    let payload = vec![0x5a; MAX_PAYLOAD_LENGTH];
    let framed = frame(&payload);

    assert_eq!(
        parse_remote_frame(&framed),
        FrameParseResult::Accepted {
            consumed: framed.len(),
            payload: &payload,
        }
    );
}

#[test]
fn exact_maximum_declared_frame_still_needs_more_when_partial() {
    let mut partial = Vec::with_capacity(4 + MAX_PAYLOAD_LENGTH - 1);
    partial.extend_from_slice(&u32::try_from(MAX_PAYLOAD_LENGTH).unwrap().to_be_bytes());
    partial.resize(4 + MAX_PAYLOAD_LENGTH - 1, 0);

    assert_eq!(parse_remote_frame(&partial), FrameParseResult::NeedMore);
}

#[test]
fn legacy_client_name_does_not_require_utf8() {
    let payload = hello_back_payload((1, 6), 2, &[0xff, 0xfe]);
    let parsed = parse_handshake(&payload, ExpectedHandshake::HelloBack);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(payload.len()));
    assert_eq!(
        parsed.handshake,
        Some(Handshake::HelloBack {
            major: 1,
            minor: 6,
            client_name: &[0xff, 0xfe],
        })
    );
}

#[test]
fn expected_state_is_explicit_instead_of_inferred_from_payload_size() {
    let hello = hello_payload((1, 6));

    assert_eq!(
        parse_handshake(&hello, ExpectedHandshake::Hello).category,
        Category::Accepted
    );
    assert_eq!(
        parse_handshake(&hello, ExpectedHandshake::HelloBack).category,
        Category::Malformed
    );
}

#[test]
fn cursor_does_not_advance_on_incomplete_or_oversized_field() {
    let incomplete = [0, 0, 0, 2, b'a'];
    let mut incomplete_cursor = ByteCursor::new(&incomplete);
    assert_eq!(
        incomplete_cursor.read_u32_length_prefixed(MAX_STRING_LENGTH),
        LengthPrefixedBytes::NeedMore
    );
    assert_eq!(incomplete_cursor.position(), 0);

    let declared = u32::try_from(MAX_STRING_LENGTH + 1).unwrap().to_be_bytes();
    let mut oversized_cursor = ByteCursor::new(&declared);
    assert_eq!(
        oversized_cursor.read_u32_length_prefixed(MAX_STRING_LENGTH),
        LengthPrefixedBytes::Oversized
    );
    assert_eq!(oversized_cursor.position(), 0);
}

#[test]
fn cursor_accepts_a_string_at_the_exact_one_mib_limit() {
    let value = vec![b'x'; MAX_STRING_LENGTH];
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    encoded.extend_from_slice(&value);
    let mut cursor = ByteCursor::new(&encoded);

    assert_eq!(
        cursor.read_u32_length_prefixed(MAX_STRING_LENGTH),
        LengthPrefixedBytes::Complete(value.as_slice())
    );
    assert_eq!(cursor.remaining(), 0);
}

#[test]
fn frozen_cpp_noop_decode_matrix_matches_all_cpp_dispatch_states() {
    let observed_contexts = [
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::ClientHandshake,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::Active,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ServerAwaitingInfo,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::Active,
        ),
    ];

    for context in observed_contexts {
        let parsed = parse_remote_message(REMOTE_CNOP_PAYLOAD, context);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(REMOTE_CNOP_PAYLOAD.len()));
        assert_eq!(parsed.message, Some(RemoteMessage::Noop));
    }

    let rejected_contexts = [
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ServerAwaitingHelloBack,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ClientHandshake,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::ServerAwaitingHelloBack,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::ServerAwaitingInfo,
        ),
    ];

    for context in rejected_contexts {
        let rejected = parse_remote_message(REMOTE_CNOP_PAYLOAD, context);
        assert_eq!(rejected.category, Category::Malformed);
        assert_eq!(rejected.consumed, None);
        assert_eq!(rejected.message, None);
    }
}

#[test]
fn complete_payload_shorter_than_a_message_code_is_malformed() {
    let short_payload = &REMOTE_CNOP_PAYLOAD[..REMOTE_CNOP_PAYLOAD.len() - 1];
    let parsed = parse_remote_message(
        short_payload,
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::Active,
        ),
    );

    assert_eq!(parsed.category, Category::Malformed);
    assert_eq!(parsed.consumed, None);
    assert_eq!(parsed.message, None);
}

#[test]
fn noop_encoder_matches_the_only_productive_cpp_send_path() {
    let productive_context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    );
    let encoded = encode_remote_message(RemoteMessage::Noop, productive_context).unwrap();
    assert_eq!(encoded.as_slice(), REMOTE_CNOP_PAYLOAD);

    let receive_only_or_invalid_contexts = [
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::ClientHandshake,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ServerToClient,
            RemoteMessageState::Active,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ServerAwaitingHelloBack,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ServerAwaitingInfo,
        ),
    ];
    for context in receive_only_or_invalid_contexts {
        assert_eq!(
            encode_remote_message(RemoteMessage::Noop, context),
            Err(RemoteEncodeError::InvalidContext)
        );
    }
}

#[test]
fn two_complete_noops_in_one_payload_are_reparsed_sequentially() {
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    );
    let mut payload = REMOTE_CNOP_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_CNOP_PAYLOAD);

    let first = parse_remote_message(&payload, context);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(REMOTE_CNOP_PAYLOAD.len()));

    let second = parse_remote_message(&payload[first.consumed.unwrap()..], context);
    assert_eq!(second.category, Category::Accepted);
    assert_eq!(second.consumed, Some(REMOTE_CNOP_PAYLOAD.len()));
    assert_eq!(
        first.consumed.unwrap() + second.consumed.unwrap(),
        payload.len()
    );
}

#[test]
fn partial_next_command_is_preserved_then_rejected_as_malformed() {
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    );
    for trailing_length in 1..REMOTE_CNOP_PAYLOAD.len() {
        let mut payload = REMOTE_CNOP_PAYLOAD.to_vec();
        payload.extend_from_slice(&REMOTE_CNOP_PAYLOAD[..trailing_length]);

        let first = parse_remote_message(&payload, context);
        assert_eq!(first.category, Category::Accepted);
        assert_eq!(first.consumed, Some(REMOTE_CNOP_PAYLOAD.len()));
        let trailing = &payload[first.consumed.unwrap()..];
        assert_eq!(trailing.len(), trailing_length);
        assert_eq!(
            parse_remote_message(trailing, context).category,
            Category::Malformed
        );
    }
}

#[test]
fn same_length_corruption_and_unknown_next_code_are_malformed() {
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::Active,
    );
    let mut corrupted = REMOTE_CNOP_PAYLOAD.to_vec();
    let final_byte = corrupted.len() - 1;
    corrupted[final_byte] ^= 1;
    assert_eq!(
        parse_remote_message(&corrupted, context).category,
        Category::Malformed
    );

    let mut payload = REMOTE_CNOP_PAYLOAD.to_vec();
    payload.extend_from_slice(&corrupted);
    let first = parse_remote_message(&payload, context);
    assert_eq!(first.category, Category::Accepted);
    let trailing = &payload[first.consumed.unwrap()..];
    assert_eq!(
        parse_remote_message(trailing, context).category,
        Category::Malformed
    );
}

#[test]
fn fixed_control_decode_matrix_matches_cpp_client_dispatch() {
    let messages = [
        (
            REMOTE_QINF_PAYLOAD,
            RemoteMessage::QueryInfo,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            REMOTE_CIAK_PAYLOAD,
            RemoteMessage::InfoAck,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            REMOTE_CROP_PAYLOAD,
            RemoteMessage::ResetOptions,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            REMOTE_COUT_PAYLOAD,
            RemoteMessage::Leave,
            &[CLIENT_ACTIVE][..],
        ),
    ];

    for (fixture, expected_message, accepted_contexts) in messages {
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            let parsed = parse_remote_message(fixture, context);
            if accepted_contexts.contains(&context) {
                assert_eq!(
                    parsed.category,
                    Category::Accepted,
                    "{expected_message:?} {context:?}"
                );
                assert_eq!(parsed.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
                assert_eq!(parsed.message, Some(expected_message));
            } else {
                assert_eq!(
                    parsed.category,
                    Category::Malformed,
                    "{expected_message:?} {context:?}"
                );
                assert_eq!(parsed.consumed, None);
                assert_eq!(parsed.message, None);
            }
        }
    }
}

#[test]
fn fixed_control_encode_matrix_matches_observed_cpp_send_sites() {
    let messages = [
        (
            RemoteMessage::QueryInfo,
            REMOTE_QINF_PAYLOAD,
            &[CLIENT_HANDSHAKE][..],
        ),
        (
            RemoteMessage::InfoAck,
            REMOTE_CIAK_PAYLOAD,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            RemoteMessage::ResetOptions,
            REMOTE_CROP_PAYLOAD,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            RemoteMessage::Leave,
            REMOTE_COUT_PAYLOAD,
            &[CLIENT_ACTIVE][..],
        ),
    ];

    for (message, fixture, observed_contexts) in messages {
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            let encoded = encode_remote_message(message, context);
            if observed_contexts.contains(&context) {
                assert_eq!(
                    encoded.unwrap().as_slice(),
                    fixture,
                    "{message:?} {context:?}"
                );
            } else {
                assert_eq!(
                    encoded,
                    Err(RemoteEncodeError::InvalidContext),
                    "{message:?} {context:?}"
                );
            }
        }
    }
}

#[test]
fn query_info_active_is_decode_only() {
    assert_eq!(
        parse_remote_message(REMOTE_QINF_PAYLOAD, CLIENT_ACTIVE).message,
        Some(RemoteMessage::QueryInfo)
    );
    assert_eq!(
        encode_remote_message(RemoteMessage::QueryInfo, CLIENT_ACTIVE),
        Err(RemoteEncodeError::InvalidContext)
    );
}

#[test]
fn every_short_fixed_control_payload_is_malformed() {
    for fixture in [
        REMOTE_QINF_PAYLOAD,
        REMOTE_CIAK_PAYLOAD,
        REMOTE_CROP_PAYLOAD,
        REMOTE_COUT_PAYLOAD,
    ] {
        for length in 0..REMOTE_MESSAGE_CODE_LENGTH {
            let parsed = parse_remote_message(&fixture[..length], CLIENT_ACTIVE);
            assert_eq!(parsed.category, Category::Malformed);
            assert_eq!(parsed.consumed, None);
            assert_eq!(parsed.message, None);
        }
    }
}

#[test]
fn same_length_fixed_control_corruption_is_malformed() {
    for fixture in [
        REMOTE_QINF_PAYLOAD,
        REMOTE_CIAK_PAYLOAD,
        REMOTE_CROP_PAYLOAD,
        REMOTE_COUT_PAYLOAD,
    ] {
        let mut corrupted = fixture.to_vec();
        let final_byte = corrupted.len() - 1;
        corrupted[final_byte] ^= 1;

        let parsed = parse_remote_message(&corrupted, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed);
        assert_eq!(parsed.consumed, None);
        assert_eq!(parsed.message, None);
    }
}

#[test]
fn multiple_fixed_controls_preserve_each_boundary_then_reject_unknown_next_code() {
    let expected = [
        (REMOTE_QINF_PAYLOAD, RemoteMessage::QueryInfo),
        (REMOTE_CIAK_PAYLOAD, RemoteMessage::InfoAck),
        (REMOTE_CROP_PAYLOAD, RemoteMessage::ResetOptions),
        (REMOTE_COUT_PAYLOAD, RemoteMessage::Leave),
    ];
    let mut payload = Vec::new();
    for (fixture, _) in expected {
        payload.extend_from_slice(fixture);
    }
    let mut unknown = REMOTE_QINF_PAYLOAD.to_vec();
    unknown[0] ^= 1;
    payload.extend_from_slice(&unknown);

    let mut offset = 0;
    for (_, expected_message) in expected {
        let parsed = parse_remote_message(&payload[offset..], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
        assert_eq!(parsed.message, Some(expected_message));
        offset += parsed.consumed.unwrap();
    }

    assert_eq!(&payload[offset..], unknown);
    let rejected = parse_remote_message(&payload[offset..], CLIENT_ACTIVE);
    assert_eq!(rejected.category, Category::Malformed);
    assert_eq!(rejected.consumed, None);
    assert_eq!(rejected.message, None);
}

#[test]
fn terminal_control_decode_matrix_matches_cpp_client_dispatch() {
    let messages = [
        (
            REMOTE_CBYE_PAYLOAD,
            RemoteMessage::Close,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
        (
            REMOTE_EBSY_PAYLOAD,
            RemoteMessage::Busy,
            &[CLIENT_HANDSHAKE][..],
        ),
        (
            REMOTE_EUNK_PAYLOAD,
            RemoteMessage::UnknownClient,
            &[CLIENT_HANDSHAKE][..],
        ),
        (
            REMOTE_EBAD_PAYLOAD,
            RemoteMessage::BadProtocol,
            &[CLIENT_HANDSHAKE, CLIENT_ACTIVE][..],
        ),
    ];

    for (fixture, expected_message, accepted_contexts) in messages {
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            let parsed = parse_remote_message(fixture, context);
            if accepted_contexts.contains(&context) {
                assert_eq!(
                    parsed.category,
                    Category::Accepted,
                    "{expected_message:?} {context:?}"
                );
                assert_eq!(parsed.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
                assert_eq!(parsed.message, Some(expected_message));
                assert!(expected_message.is_terminal());
            } else {
                assert_eq!(
                    parsed.category,
                    Category::Malformed,
                    "{expected_message:?} {context:?}"
                );
                assert_eq!(parsed.consumed, None);
                assert_eq!(parsed.message, None);
            }
        }
    }
}

#[test]
fn terminal_control_encode_matrix_is_independent_and_fail_closed() {
    let decode_only = [
        RemoteMessage::Close,
        RemoteMessage::Busy,
        RemoteMessage::UnknownClient,
    ];
    for message in decode_only {
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            assert_eq!(
                encode_remote_message(message, context),
                Err(RemoteEncodeError::InvalidContext),
                "{message:?} {context:?}"
            );
        }
    }

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let encoded = encode_remote_message(RemoteMessage::BadProtocol, context);
        if context == CLIENT_HANDSHAKE {
            assert_eq!(encoded.unwrap().as_slice(), REMOTE_EBAD_PAYLOAD);
        } else {
            assert_eq!(
                encoded,
                Err(RemoteEncodeError::InvalidContext),
                "BadProtocol {context:?}"
            );
        }
    }
}

#[test]
fn bad_protocol_active_decode_does_not_authorize_active_encode() {
    assert_eq!(
        parse_remote_message(REMOTE_EBAD_PAYLOAD, CLIENT_ACTIVE).message,
        Some(RemoteMessage::BadProtocol)
    );
    assert_eq!(
        encode_remote_message(RemoteMessage::BadProtocol, CLIENT_ACTIVE),
        Err(RemoteEncodeError::InvalidContext)
    );
}

#[test]
fn terminal_metadata_is_true_only_for_terminal_control_messages() {
    for message in [
        RemoteMessage::Close,
        RemoteMessage::Busy,
        RemoteMessage::UnknownClient,
        RemoteMessage::BadProtocol,
    ] {
        assert!(message.is_terminal(), "{message:?}");
    }

    for message in [
        RemoteMessage::Noop,
        RemoteMessage::QueryInfo,
        RemoteMessage::InfoAck,
        RemoteMessage::ResetOptions,
        RemoteMessage::Leave,
    ] {
        assert!(!message.is_terminal(), "{message:?}");
    }
}

#[test]
fn every_short_terminal_control_payload_is_malformed() {
    for fixture in [
        REMOTE_CBYE_PAYLOAD,
        REMOTE_EBSY_PAYLOAD,
        REMOTE_EUNK_PAYLOAD,
        REMOTE_EBAD_PAYLOAD,
    ] {
        for length in 0..REMOTE_MESSAGE_CODE_LENGTH {
            let parsed = parse_remote_message(&fixture[..length], CLIENT_HANDSHAKE);
            assert_eq!(parsed.category, Category::Malformed);
            assert_eq!(parsed.consumed, None);
            assert_eq!(parsed.message, None);
        }
    }
}

#[test]
fn every_byte_mutation_of_terminal_control_fixtures_is_malformed() {
    for fixture in [
        REMOTE_CBYE_PAYLOAD,
        REMOTE_EBSY_PAYLOAD,
        REMOTE_EUNK_PAYLOAD,
        REMOTE_EBAD_PAYLOAD,
    ] {
        for byte_index in 0..REMOTE_MESSAGE_CODE_LENGTH {
            let mut corrupted = fixture.to_vec();
            corrupted[byte_index] ^= 1;
            let parsed = parse_remote_message(&corrupted, CLIENT_HANDSHAKE);
            assert_eq!(
                parsed.category,
                Category::Malformed,
                "fixture={fixture:?} byte_index={byte_index}"
            );
            assert_eq!(parsed.consumed, None);
            assert_eq!(parsed.message, None);
        }
    }
}

#[test]
fn nonterminal_then_terminal_commands_preserve_both_boundaries() {
    let mut payload = REMOTE_QINF_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_EBAD_PAYLOAD);

    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(first.message, Some(RemoteMessage::QueryInfo));
    assert!(!first.message.unwrap().is_terminal());

    let second = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(second.category, Category::Accepted);
    assert_eq!(second.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(second.message, Some(RemoteMessage::BadProtocol));
    assert!(second.message.unwrap().is_terminal());
}

#[test]
fn caller_policy_stops_after_terminal_and_does_not_reparse_trailing_bytes() {
    let mut payload = REMOTE_CBYE_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_QINF_PAYLOAD);

    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    let message = first.message.unwrap();
    assert!(message.is_terminal());

    let mut reparsed = false;
    if !message.is_terminal() {
        reparsed = true;
        let _ = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_ACTIVE);
    }
    assert!(!reparsed);
    assert_eq!(
        &payload[first.consumed.unwrap()..],
        REMOTE_QINF_PAYLOAD,
        "parser preserves trailing bytes; Rust caller policy chooses not to reparse them"
    );
}

#[test]
fn nonterminal_caller_reparses_and_rejects_next_unknown_code() {
    let mut unknown = REMOTE_EBAD_PAYLOAD.to_vec();
    unknown[0] ^= 1;
    let mut payload = REMOTE_QINF_PAYLOAD.to_vec();
    payload.extend_from_slice(&unknown);

    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.message, Some(RemoteMessage::QueryInfo));
    assert!(!first.message.unwrap().is_terminal());

    let next = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(next.category, Category::Malformed);
    assert_eq!(next.consumed, None);
    assert_eq!(next.message, None);
}

#[test]
fn incompatible_version_fixture_decodes_and_encodes_productive_1_6() {
    let parsed = parse_remote_message(REMOTE_EICV_1_6_PAYLOAD, CLIENT_HANDSHAKE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(8));
    assert_eq!(
        parsed.message,
        Some(RemoteMessage::IncompatibleVersion { major: 1, minor: 6 })
    );
    assert!(parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 8];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::IncompatibleVersion { major: 1, minor: 6 },
            CLIENT_HANDSHAKE,
            &mut output,
        ),
        Ok(8)
    );
    assert_eq!(output.as_slice(), REMOTE_EICV_1_6_PAYLOAD);
}

#[test]
fn incompatible_version_decode_matrix_is_only_server_to_client_handshake() {
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(REMOTE_EICV_1_6_PAYLOAD, context);
        if context == CLIENT_HANDSHAKE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(8));
            assert_eq!(
                parsed.message,
                Some(RemoteMessage::IncompatibleVersion { major: 1, minor: 6 })
            );
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None);
            assert_eq!(parsed.message, None);
        }
    }
}

#[test]
fn incompatible_version_encode_matrix_is_only_productive_1_6_handshake() {
    let message = RemoteMessage::IncompatibleVersion { major: 1, minor: 6 };
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let mut output = [0xa5; 8];
        let before = output;
        let encoded = encode_remote_message_to(message, context, &mut output);
        if context == CLIENT_HANDSHAKE {
            assert_eq!(encoded, Ok(8));
            assert_eq!(output.as_slice(), REMOTE_EICV_1_6_PAYLOAD);
        } else {
            assert_eq!(
                encoded,
                Err(RemoteEncodeToError::Encode(
                    RemoteEncodeError::InvalidContext
                )),
                "{context:?}"
            );
            assert_eq!(output, before, "{context:?}");
        }
    }
}

#[test]
fn incompatible_version_old_encoder_requires_output_buffer_in_every_context() {
    let message = RemoteMessage::IncompatibleVersion { major: 1, minor: 6 };
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        assert_eq!(
            encode_remote_message(message, context),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{context:?}"
        );
    }
}

#[test]
fn encode_to_preserves_fieldless_api_bytes_and_suffix() {
    let cases = [
        (
            RemoteMessage::Noop,
            REMOTE_CNOP_PAYLOAD,
            RemoteMessageContext::new(
                RemoteMessageDirection::ClientToServer,
                RemoteMessageState::Active,
            ),
        ),
        (RemoteMessage::KeepAlive, REMOTE_CALV_PAYLOAD, CLIENT_ACTIVE),
        (
            RemoteMessage::QueryInfo,
            REMOTE_QINF_PAYLOAD,
            CLIENT_HANDSHAKE,
        ),
        (
            RemoteMessage::InfoAck,
            REMOTE_CIAK_PAYLOAD,
            CLIENT_HANDSHAKE,
        ),
        (
            RemoteMessage::ResetOptions,
            REMOTE_CROP_PAYLOAD,
            CLIENT_ACTIVE,
        ),
        (RemoteMessage::Leave, REMOTE_COUT_PAYLOAD, CLIENT_ACTIVE),
        (
            RemoteMessage::BadProtocol,
            REMOTE_EBAD_PAYLOAD,
            CLIENT_HANDSHAKE,
        ),
    ];
    for (message, fixture, context) in cases {
        let mut output = [0xa5; 9];
        assert_eq!(
            encode_remote_message_to(message, context, &mut output),
            Ok(4)
        );
        assert_eq!(&output[..4], fixture, "{message:?}");
        assert_eq!(&output[4..], &[0xa5; 5], "{message:?}");
    }
}

#[test]
fn encode_to_fieldless_short_buffer_and_invalid_context_do_not_mutate() {
    let mut short = [0xa5; 3];
    let short_before = short;
    assert_eq!(
        encode_remote_message_to(RemoteMessage::QueryInfo, CLIENT_HANDSHAKE, &mut short),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 4,
            available: 3,
        })
    );
    assert_eq!(short, short_before);

    let mut invalid = [0xa5; 4];
    let invalid_before = invalid;
    assert_eq!(
        encode_remote_message_to(RemoteMessage::QueryInfo, CLIENT_ACTIVE, &mut invalid),
        Err(RemoteEncodeToError::Encode(
            RemoteEncodeError::InvalidContext
        ))
    );
    assert_eq!(invalid, invalid_before);
}

#[test]
fn incompatible_version_decodes_all_signed_i16_bit_patterns_structurally() {
    for (major, minor) in [(i16::MIN, i16::MAX), (i16::MAX, i16::MIN)] {
        let mut payload = REMOTE_EICV_1_6_PAYLOAD.to_vec();
        payload[4..6].copy_from_slice(&major.to_be_bytes());
        payload[6..8].copy_from_slice(&minor.to_be_bytes());
        let parsed = parse_remote_message(&payload, CLIENT_HANDSHAKE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(8));
        assert_eq!(
            parsed.message,
            Some(RemoteMessage::IncompatibleVersion { major, minor })
        );
    }
}

#[test]
fn every_short_incompatible_version_payload_is_malformed_without_boundary() {
    for length in 0..REMOTE_EICV_1_6_PAYLOAD.len() {
        let parsed = parse_remote_message(&REMOTE_EICV_1_6_PAYLOAD[..length], CLIENT_HANDSHAKE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn every_incompatible_version_code_byte_mutation_is_malformed() {
    for byte_index in 0..REMOTE_MESSAGE_CODE_LENGTH {
        let mut corrupted = REMOTE_EICV_1_6_PAYLOAD.to_vec();
        corrupted[byte_index] ^= 1;
        let parsed = parse_remote_message(&corrupted, CLIENT_HANDSHAKE);
        assert_eq!(
            parsed.category,
            Category::Malformed,
            "byte_index={byte_index}"
        );
        assert_eq!(parsed.consumed, None);
        assert_eq!(parsed.message, None);
    }
}

#[test]
fn every_incompatible_version_field_byte_mutation_is_structurally_accepted() {
    for byte_index in REMOTE_MESSAGE_CODE_LENGTH..REMOTE_EICV_1_6_PAYLOAD.len() {
        let mut mutated = REMOTE_EICV_1_6_PAYLOAD.to_vec();
        mutated[byte_index] ^= 1;
        let parsed = parse_remote_message(&mutated, CLIENT_HANDSHAKE);
        assert_eq!(
            parsed.category,
            Category::Accepted,
            "byte_index={byte_index}"
        );
        assert_eq!(parsed.consumed, Some(8));
        assert!(matches!(
            parsed.message,
            Some(RemoteMessage::IncompatibleVersion { .. })
        ));
    }
}

#[test]
fn incompatible_version_trailing_bytes_are_preserved_but_terminal_caller_stops() {
    let mut payload = REMOTE_EICV_1_6_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_QINF_PAYLOAD);
    let first = parse_remote_message(&payload, CLIENT_HANDSHAKE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(8));
    let message = first.message.unwrap();
    assert!(message.is_terminal());
    assert_eq!(&payload[first.consumed.unwrap()..], REMOTE_QINF_PAYLOAD);

    let mut reparsed = false;
    if !message.is_terminal() {
        reparsed = true;
        let _ = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_HANDSHAKE);
    }
    assert!(!reparsed);
}

#[test]
fn incompatible_version_short_output_preserves_all_bytes() {
    let mut output = [0xa5; 7];
    let before = output;
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::IncompatibleVersion { major: 1, minor: 6 },
            CLIENT_HANDSHAKE,
            &mut output,
        ),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 8,
            available: 7,
        })
    );
    assert_eq!(output, before);
}

#[test]
fn incompatible_version_large_output_preserves_suffix() {
    let mut output = [0xa5; 13];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::IncompatibleVersion { major: 1, minor: 6 },
            CLIENT_HANDSHAKE,
            &mut output,
        ),
        Ok(8)
    );
    assert_eq!(&output[..8], REMOTE_EICV_1_6_PAYLOAD);
    assert_eq!(&output[8..], &[0xa5; 5]);
}

#[test]
fn incompatible_version_validation_precedes_capacity_and_never_partially_writes() {
    let invalid_context = RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::Active,
    );
    let mut output = [0xa5; 0];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::IncompatibleVersion { major: 9, minor: 9 },
            invalid_context,
            &mut output,
        ),
        Err(RemoteEncodeToError::Encode(
            RemoteEncodeError::InvalidContext
        ))
    );

    let mut unsupported = [0xa5; 8];
    let before = unsupported;
    for (major, minor) in [(1, 5), (i16::MIN, i16::MAX)] {
        assert_eq!(
            encode_remote_message_to(
                RemoteMessage::IncompatibleVersion { major, minor },
                CLIENT_HANDSHAKE,
                &mut unsupported,
            ),
            Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::UnsupportedValue
            ))
        );
        assert_eq!(unsupported, before);
    }
}

#[test]
fn screen_saver_fixtures_decode_and_encode_productive_boolean_values() {
    for (raw, fixture) in [(0, REMOTE_CSEC_OFF_PAYLOAD), (1, REMOTE_CSEC_ON_PAYLOAD)] {
        let parsed = parse_remote_message(fixture, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(5));
        assert_eq!(parsed.message, Some(RemoteMessage::ScreenSaver { raw }));
        assert!(!parsed.message.unwrap().is_terminal());

        let mut output = [0xa5; 5];
        assert_eq!(
            encode_remote_message_to(
                RemoteMessage::ScreenSaver { raw },
                CLIENT_ACTIVE,
                &mut output
            ),
            Ok(5)
        );
        assert_eq!(output.as_slice(), fixture);
    }
}

#[test]
fn screen_saver_decode_matrix_is_only_server_to_client_active() {
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(REMOTE_CSEC_ON_PAYLOAD, context);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(5));
            assert_eq!(parsed.message, Some(RemoteMessage::ScreenSaver { raw: 1 }));
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None, "{context:?}");
            assert_eq!(parsed.message, None, "{context:?}");
        }
    }
}

#[test]
fn screen_saver_encode_matrix_is_only_productive_server_to_client_active() {
    for raw in [0, 1] {
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            let mut output = [0xa5; 5];
            let before = output;
            let encoded =
                encode_remote_message_to(RemoteMessage::ScreenSaver { raw }, context, &mut output);
            if context == CLIENT_ACTIVE {
                assert_eq!(encoded, Ok(5), "raw={raw} {context:?}");
                assert_eq!(
                    output.as_slice(),
                    if raw == 0 {
                        REMOTE_CSEC_OFF_PAYLOAD
                    } else {
                        REMOTE_CSEC_ON_PAYLOAD
                    }
                );
            } else {
                assert_eq!(
                    encoded,
                    Err(RemoteEncodeToError::Encode(
                        RemoteEncodeError::InvalidContext
                    )),
                    "raw={raw} {context:?}"
                );
                assert_eq!(output, before, "raw={raw} {context:?}");
            }
        }
    }
}

#[test]
fn screen_saver_old_encoder_requires_output_buffer_in_every_context() {
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        assert_eq!(
            encode_remote_message(RemoteMessage::ScreenSaver { raw: 1 }, context),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{context:?}"
        );
    }
}

#[test]
fn screen_saver_decodes_all_u8_values_structurally() {
    for raw in u8::MIN..=u8::MAX {
        let payload = [b'C', b'S', b'E', b'C', raw];
        let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted, "raw={raw}");
        assert_eq!(parsed.consumed, Some(5), "raw={raw}");
        assert_eq!(
            parsed.message,
            Some(RemoteMessage::ScreenSaver { raw }),
            "raw={raw}"
        );
    }
}

#[test]
fn every_short_screen_saver_payload_is_malformed_without_boundary() {
    for length in 0..REMOTE_CSEC_ON_PAYLOAD.len() {
        let parsed = parse_remote_message(&REMOTE_CSEC_ON_PAYLOAD[..length], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn every_screen_saver_code_byte_mutation_is_malformed() {
    for byte_index in 0..REMOTE_MESSAGE_CODE_LENGTH {
        let mut corrupted = REMOTE_CSEC_ON_PAYLOAD.to_vec();
        corrupted[byte_index] ^= 1;
        let parsed = parse_remote_message(&corrupted, CLIENT_ACTIVE);
        assert_eq!(
            parsed.category,
            Category::Malformed,
            "byte_index={byte_index}"
        );
        assert_eq!(parsed.consumed, None);
        assert_eq!(parsed.message, None);
    }
}

#[test]
fn screen_saver_trailing_message_is_preserved_and_reparsed() {
    let mut payload = REMOTE_CSEC_ON_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_CNOP_PAYLOAD);
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(5));
    assert_eq!(first.message, Some(RemoteMessage::ScreenSaver { raw: 1 }));
    assert!(!first.message.unwrap().is_terminal());

    let next = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(next.category, Category::Accepted);
    assert_eq!(next.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(next.message, Some(RemoteMessage::Noop));
}

#[test]
fn screen_saver_short_output_preserves_all_bytes() {
    let mut output = [0xa5; 4];
    let before = output;
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::ScreenSaver { raw: 1 },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(output, before);
}

#[test]
fn screen_saver_large_output_preserves_suffix() {
    let mut output = [0xa5; 10];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::ScreenSaver { raw: 0 },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Ok(5)
    );
    assert_eq!(&output[..5], REMOTE_CSEC_OFF_PAYLOAD);
    assert_eq!(&output[5..], &[0xa5; 5]);
}

#[test]
fn screen_saver_validation_precedes_capacity_and_never_partially_writes() {
    let invalid_context = RemoteMessageContext::new(
        RemoteMessageDirection::ServerToClient,
        RemoteMessageState::ClientHandshake,
    );
    let mut empty = [0xa5; 0];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::ScreenSaver { raw: 2 },
            invalid_context,
            &mut empty,
        ),
        Err(RemoteEncodeToError::Encode(
            RemoteEncodeError::InvalidContext
        ))
    );

    let mut unsupported = [0xa5; 4];
    let before = unsupported;
    for raw in [2, u8::MAX] {
        assert_eq!(
            encode_remote_message_to(
                RemoteMessage::ScreenSaver { raw },
                CLIENT_ACTIVE,
                &mut unsupported,
            ),
            Err(RemoteEncodeToError::Encode(
                RemoteEncodeError::UnsupportedValue
            ))
        );
        assert_eq!(unsupported, before, "raw={raw}");
    }
}

#[test]
fn dmmv_active_payload_decodes_and_encodes_signed_coordinates() {
    let payload = [b'D', b'M', b'M', b'V', 0x12, 0x34, 0xed, 0xcc];
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(8));
    assert_eq!(
        parsed.message,
        Some(RemoteMessage::MouseMove {
            x: 0x1234,
            y: -0x1234,
        })
    );

    let mut output = [0xa5; 8];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::MouseMove {
                x: 0x1234,
                y: -0x1234,
            },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Ok(8)
    );
    assert_eq!(output, payload);
}

#[test]
fn dmrm_active_payload_decodes_and_encodes_signed_deltas() {
    let payload = [b'D', b'M', b'R', b'M', 0x12, 0x34, 0xed, 0xcc];
    let message = RemoteMessage::MouseRelativeMove {
        dx: 0x1234,
        dy: -0x1234,
    };
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(8));
    assert_eq!(parsed.message, Some(message));
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 8];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Ok(8)
    );
    assert_eq!(output, payload);
}

#[test]
fn dmrm_context_matrix_and_short_output_fail_closed() {
    let payload = [b'D', b'M', b'R', b'M', 0, 1, 0, 2];
    let message = RemoteMessage::MouseRelativeMove { dx: 1, dy: 2 };
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(&payload, context);
        let mut output = [0xa5; 8];
        let before = output;
        let encoded = encode_remote_message_to(message, context, &mut output);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(8), "{context:?}");
            assert_eq!(parsed.message, Some(message), "{context:?}");
            assert_eq!(encoded, Ok(8), "{context:?}");
            assert_eq!(output, payload, "{context:?}");
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None, "{context:?}");
            assert_eq!(parsed.message, None, "{context:?}");
            assert_eq!(
                encoded,
                Err(RemoteEncodeToError::Encode(
                    RemoteEncodeError::InvalidContext
                )),
                "{context:?}"
            );
            assert_eq!(output, before, "{context:?}");
        }
    }

    let mut short = [0xa5; 7];
    let before = short;
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut short),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 8,
            available: 7,
        })
    );
    assert_eq!(short, before);
    assert_eq!(
        encode_remote_message(message, CLIENT_ACTIVE),
        Err(RemoteEncodeError::RequiresOutputBuffer)
    );
}

#[test]
fn dmrm_signed_i16_boundaries_are_byte_identical() {
    for (dx, dy, expected) in [
        (
            i16::MIN,
            i16::MAX,
            [b'D', b'M', b'R', b'M', 0x80, 0x00, 0x7f, 0xff],
        ),
        (-1, 0, [b'D', b'M', b'R', b'M', 0xff, 0xff, 0x00, 0x00]),
    ] {
        let message = RemoteMessage::MouseRelativeMove { dx, dy };
        let parsed = parse_remote_message(&expected, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(8));
        assert_eq!(parsed.message, Some(message));
        let mut output = [0xa5; 8];
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
            Ok(8)
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn every_short_dmrm_payload_is_malformed_without_boundary() {
    let payload = [b'D', b'M', b'R', b'M', 0, 1, 0, 2];
    for length in 0..payload.len() {
        let parsed = parse_remote_message(&payload[..length], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn dmrm_boundary_preserves_trailing_command() {
    let payload = b"DMRM\x80\x00\x7f\xffCROP";
    let first = parse_remote_message(payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(8));
    assert_eq!(
        first.message,
        Some(RemoteMessage::MouseRelativeMove {
            dx: i16::MIN,
            dy: i16::MAX,
        })
    );
    assert!(!first.message.unwrap().is_terminal());
    let trailing = parse_remote_message(&payload[8..], CLIENT_ACTIVE);
    assert_eq!(trailing.category, Category::Accepted);
    assert_eq!(trailing.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(trailing.message, Some(RemoteMessage::ResetOptions));
}

#[test]
fn dmmv_rejects_non_active_contexts_and_short_output_without_mutation() {
    let payload = [b'D', b'M', b'M', b'V', 0, 1, 0, 2];
    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(&payload, context);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted);
        } else {
            assert_eq!(parsed.category, Category::Malformed);
        }
    }

    let mut output = [0xa5; 7];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::MouseMove { x: 1, y: 2 },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 8,
            available: 7,
        })
    );
    assert_eq!(output, [0xa5; 7]);
}

#[test]
fn dmmv_signed_i16_boundaries_are_byte_identical() {
    for (x, y, expected) in [
        (
            i16::MIN,
            i16::MAX,
            [b'D', b'M', b'M', b'V', 0x80, 0x00, 0x7f, 0xff],
        ),
        (-1, 0, [b'D', b'M', b'M', b'V', 0xff, 0xff, 0x00, 0x00]),
    ] {
        let parsed = parse_remote_message(&expected, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.message, Some(RemoteMessage::MouseMove { x, y }));
        let mut output = [0xa5; 8];
        assert_eq!(
            encode_remote_message_to(
                RemoteMessage::MouseMove { x, y },
                CLIENT_ACTIVE,
                &mut output
            ),
            Ok(8)
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn dkdn_active_payload_decodes_and_encodes_three_unsigned_fields() {
    let payload = [b'D', b'K', b'D', b'N', 0x12, 0x34, 0x80, 0x01, 0xff, 0xff];
    let message = RemoteMessage::KeyDown {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        button: u16::MAX,
    };
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(10));
    assert_eq!(parsed.message, Some(message));
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 10];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Ok(10)
    );
    assert_eq!(output, payload);
}

#[test]
fn dkup_active_payload_decodes_and_encodes_three_unsigned_fields() {
    let payload = [b'D', b'K', b'U', b'P', 0x12, 0x34, 0x80, 0x01, 0xff, 0xff];
    let message = RemoteMessage::KeyUp {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        button: u16::MAX,
    };
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(10));
    assert_eq!(parsed.message, Some(message));
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 10];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Ok(10)
    );
    assert_eq!(output, payload);
}

#[test]
fn dkrp_active_payload_decodes_and_encodes_four_unsigned_fields() {
    let payload = [
        b'D', b'K', b'R', b'P', 0x12, 0x34, 0x80, 0x01, 0xff, 0xff, 0x00, 0x02,
    ];
    let message = RemoteMessage::KeyRepeat {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        count: u16::MAX,
        button: 2,
    };
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(12));
    assert_eq!(parsed.message, Some(message));
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 12];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Ok(12)
    );
    assert_eq!(output, payload);
}

#[test]
fn dkrp_context_matrix_is_only_server_to_client_active() {
    let payload = [b'D', b'K', b'R', b'P', 0, 1, 0, 2, 0, 3, 0, 4];
    let message = RemoteMessage::KeyRepeat {
        key_id: 1,
        modifier_mask: 2,
        count: 3,
        button: 4,
    };

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(&payload, context);
        let mut output = [0xa5; 12];
        let before = output;
        let encoded = encode_remote_message_to(message, context, &mut output);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(12), "{context:?}");
            assert_eq!(parsed.message, Some(message), "{context:?}");
            assert_eq!(encoded, Ok(12), "{context:?}");
            assert_eq!(output, payload, "{context:?}");
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None, "{context:?}");
            assert_eq!(parsed.message, None, "{context:?}");
            assert_eq!(
                encoded,
                Err(RemoteEncodeToError::Encode(
                    RemoteEncodeError::InvalidContext
                )),
                "{context:?}"
            );
            assert_eq!(output, before, "{context:?}");
        }
    }
}

#[test]
fn dkrp_u16_boundaries_are_byte_identical() {
    for (key_id, modifier_mask, count, button, expected) in [
        (
            u16::MIN,
            u16::MAX,
            u16::MIN,
            u16::MAX,
            [
                b'D', b'K', b'R', b'P', 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
            ],
        ),
        (
            u16::MAX,
            u16::MIN,
            u16::MAX,
            u16::MIN,
            [
                b'D', b'K', b'R', b'P', 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            ],
        ),
    ] {
        let message = RemoteMessage::KeyRepeat {
            key_id,
            modifier_mask,
            count,
            button,
        };
        let parsed = parse_remote_message(&expected, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(12));
        assert_eq!(parsed.message, Some(message));

        let mut output = [0xa5; 12];
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
            Ok(12)
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn every_short_dkrp_payload_is_malformed_without_boundary() {
    let payload = [b'D', b'K', b'R', b'P', 0, 1, 0, 2, 0, 3, 0, 4];
    for length in 0..payload.len() {
        let parsed = parse_remote_message(&payload[..length], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn dkrp_boundary_preserves_trailing_command() {
    let mut payload = b"DKRP\x12\x34\x80\x01\xff\xff\x00\x02CROP".to_vec();
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(12));
    assert_eq!(
        first.message,
        Some(RemoteMessage::KeyRepeat {
            key_id: 0x1234,
            modifier_mask: 0x8001,
            count: u16::MAX,
            button: 2,
        })
    );
    assert!(!first.message.unwrap().is_terminal());

    payload.drain(..first.consumed.unwrap());
    let trailing = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(trailing.category, Category::Accepted);
    assert_eq!(trailing.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(trailing.message, Some(RemoteMessage::ResetOptions));
}

#[test]
fn dkrp_short_output_and_old_encoder_fail_without_partial_output() {
    let message = RemoteMessage::KeyRepeat {
        key_id: 1,
        modifier_mask: 2,
        count: 3,
        button: 4,
    };
    let mut output = [0xa5; 11];
    let before = output;
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 12,
            available: 11,
        })
    );
    assert_eq!(output, before);

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        assert_eq!(
            encode_remote_message(message, context),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{context:?}"
        );
    }
}

#[test]
fn dkup_context_matrix_is_only_server_to_client_active() {
    let payload = [b'D', b'K', b'U', b'P', 0, 1, 0, 2, 0, 3];
    let message = RemoteMessage::KeyUp {
        key_id: 1,
        modifier_mask: 2,
        button: 3,
    };

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(&payload, context);
        let mut output = [0xa5; 10];
        let before = output;
        let encoded = encode_remote_message_to(message, context, &mut output);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(10), "{context:?}");
            assert_eq!(parsed.message, Some(message), "{context:?}");
            assert_eq!(encoded, Ok(10), "{context:?}");
            assert_eq!(output, payload, "{context:?}");
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None, "{context:?}");
            assert_eq!(parsed.message, None, "{context:?}");
            assert_eq!(
                encoded,
                Err(RemoteEncodeToError::Encode(
                    RemoteEncodeError::InvalidContext
                )),
                "{context:?}"
            );
            assert_eq!(output, before, "{context:?}");
        }
    }
}

#[test]
fn dkup_u16_boundaries_are_byte_identical() {
    for (key_id, modifier_mask, button, expected) in [
        (
            u16::MIN,
            u16::MAX,
            u16::MIN,
            [b'D', b'K', b'U', b'P', 0x00, 0x00, 0xff, 0xff, 0x00, 0x00],
        ),
        (
            u16::MAX,
            u16::MIN,
            u16::MAX,
            [b'D', b'K', b'U', b'P', 0xff, 0xff, 0x00, 0x00, 0xff, 0xff],
        ),
    ] {
        let message = RemoteMessage::KeyUp {
            key_id,
            modifier_mask,
            button,
        };
        let parsed = parse_remote_message(&expected, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(10));
        assert_eq!(parsed.message, Some(message));

        let mut output = [0xa5; 10];
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
            Ok(10)
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn every_short_dkup_payload_is_malformed_without_boundary() {
    let payload = [b'D', b'K', b'U', b'P', 0, 1, 0, 2, 0, 3];
    for length in 0..payload.len() {
        let parsed = parse_remote_message(&payload[..length], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn dkup_boundary_preserves_trailing_command() {
    let mut payload = b"DKUP\x12\x34\x80\x01\xff\xffCROP".to_vec();
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(10));
    assert_eq!(
        first.message,
        Some(RemoteMessage::KeyUp {
            key_id: 0x1234,
            modifier_mask: 0x8001,
            button: u16::MAX,
        })
    );
    assert!(!first.message.unwrap().is_terminal());

    payload.drain(..first.consumed.unwrap());
    let trailing = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(trailing.category, Category::Accepted);
    assert_eq!(trailing.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(trailing.message, Some(RemoteMessage::ResetOptions));
}

#[test]
fn dkup_short_output_and_old_encoder_fail_without_partial_output() {
    let message = RemoteMessage::KeyUp {
        key_id: 1,
        modifier_mask: 2,
        button: 3,
    };
    let mut output = [0xa5; 9];
    let before = output;
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 10,
            available: 9,
        })
    );
    assert_eq!(output, before);

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        assert_eq!(
            encode_remote_message(message, context),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{context:?}"
        );
    }
}

#[test]
fn frozen_cpp_dkdn_frame_decodes_and_encodes_byte_identically() {
    let payload = accepted_payload(REMOTE_DKDN_BOUNDARY_FRAME);
    let message = RemoteMessage::KeyDown {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        button: u16::MAX,
    };
    let parsed = parse_remote_message(payload, CLIENT_ACTIVE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(10));
    assert_eq!(parsed.message, Some(message));

    let mut encoded = [0xa5; 10];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut encoded),
        Ok(10)
    );
    assert_eq!(encoded.as_slice(), payload);
}

#[test]
fn frozen_cpp_dkup_frame_decodes_and_encodes_byte_identically() {
    let payload = accepted_payload(REMOTE_DKUP_BOUNDARY_FRAME);
    let message = RemoteMessage::KeyUp {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        button: u16::MAX,
    };
    let parsed = parse_remote_message(payload, CLIENT_ACTIVE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(10));
    assert_eq!(parsed.message, Some(message));

    let mut encoded = [0xa5; 10];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut encoded),
        Ok(10)
    );
    assert_eq!(encoded.as_slice(), payload);
}

#[test]
fn frozen_cpp_dkrp_frame_decodes_and_encodes_byte_identically() {
    let payload = accepted_payload(REMOTE_DKRP_BOUNDARY_FRAME);
    let message = RemoteMessage::KeyRepeat {
        key_id: 0x1234,
        modifier_mask: 0x8001,
        count: u16::MAX,
        button: 2,
    };
    let parsed = parse_remote_message(payload, CLIENT_ACTIVE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(12));
    assert_eq!(parsed.message, Some(message));

    let mut encoded = [0xa5; 12];
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut encoded),
        Ok(12)
    );
    assert_eq!(encoded.as_slice(), payload);
}

#[test]
fn dkdn_context_matrix_is_only_server_to_client_active() {
    let payload = [b'D', b'K', b'D', b'N', 0, 1, 0, 2, 0, 3];
    let message = RemoteMessage::KeyDown {
        key_id: 1,
        modifier_mask: 2,
        button: 3,
    };

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(&payload, context);
        let mut output = [0xa5; 10];
        let before = output;
        let encoded = encode_remote_message_to(message, context, &mut output);
        if context == CLIENT_ACTIVE {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(10), "{context:?}");
            assert_eq!(parsed.message, Some(message), "{context:?}");
            assert_eq!(encoded, Ok(10), "{context:?}");
            assert_eq!(output, payload, "{context:?}");
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None, "{context:?}");
            assert_eq!(parsed.message, None, "{context:?}");
            assert_eq!(
                encoded,
                Err(RemoteEncodeToError::Encode(
                    RemoteEncodeError::InvalidContext
                )),
                "{context:?}"
            );
            assert_eq!(output, before, "{context:?}");
        }
    }
}

#[test]
fn dkdn_u16_boundaries_are_byte_identical() {
    for (key_id, modifier_mask, button, expected) in [
        (
            u16::MIN,
            u16::MAX,
            u16::MIN,
            [b'D', b'K', b'D', b'N', 0x00, 0x00, 0xff, 0xff, 0x00, 0x00],
        ),
        (
            u16::MAX,
            u16::MIN,
            u16::MAX,
            [b'D', b'K', b'D', b'N', 0xff, 0xff, 0x00, 0x00, 0xff, 0xff],
        ),
    ] {
        let message = RemoteMessage::KeyDown {
            key_id,
            modifier_mask,
            button,
        };
        let parsed = parse_remote_message(&expected, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted);
        assert_eq!(parsed.consumed, Some(10));
        assert_eq!(parsed.message, Some(message));

        let mut output = [0xa5; 10];
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
            Ok(10)
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn every_short_dkdn_payload_is_malformed_without_boundary() {
    let payload = [b'D', b'K', b'D', b'N', 0, 1, 0, 2, 0, 3];
    for length in 0..payload.len() {
        let parsed = parse_remote_message(&payload[..length], CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Malformed, "length={length}");
        assert_eq!(parsed.consumed, None, "length={length}");
        assert_eq!(parsed.message, None, "length={length}");
    }
}

#[test]
fn dkdn_boundary_preserves_trailing_command() {
    let mut payload = b"DKDN\x12\x34\x80\x01\xff\xffCROP".to_vec();
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.category, Category::Accepted);
    assert_eq!(first.consumed, Some(10));
    assert_eq!(
        first.message,
        Some(RemoteMessage::KeyDown {
            key_id: 0x1234,
            modifier_mask: 0x8001,
            button: u16::MAX,
        })
    );
    assert!(!first.message.unwrap().is_terminal());

    payload.drain(..first.consumed.unwrap());
    let trailing = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(trailing.category, Category::Accepted);
    assert_eq!(trailing.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(trailing.message, Some(RemoteMessage::ResetOptions));
}

#[test]
fn dkdn_short_output_and_old_encoder_fail_without_partial_output() {
    let message = RemoteMessage::KeyDown {
        key_id: 1,
        modifier_mask: 2,
        button: 3,
    };
    let mut output = [0xa5; 9];
    let before = output;
    assert_eq!(
        encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
        Err(RemoteEncodeToError::OutputTooSmall {
            required: 10,
            available: 9,
        })
    );
    assert_eq!(output, before);

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        assert_eq!(
            encode_remote_message(message, context),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{context:?}"
        );
    }
}

#[test]
fn frozen_cpp_mouse_button_fixtures_decode_and_encode_byte_identically() {
    for (fixture, message) in [
        (
            REMOTE_DMDN_BUTTON1_PAYLOAD,
            RemoteMessage::MouseDown { button: 1 },
        ),
        (
            REMOTE_DMUP_BUTTON1_PAYLOAD,
            RemoteMessage::MouseUp { button: 1 },
        ),
    ] {
        let parsed = parse_remote_message(fixture, CLIENT_ACTIVE);
        assert_eq!(parsed.category, Category::Accepted, "{message:?}");
        assert_eq!(parsed.consumed, Some(5), "{message:?}");
        assert_eq!(parsed.message, Some(message), "{message:?}");

        let mut output = [0xa5; 5];
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
            Ok(5),
            "{message:?}"
        );
        assert_eq!(output.as_slice(), fixture, "{message:?}");
    }
}

#[test]
fn mouse_down_decodes_and_encodes_one_raw_button_id() {
    let payload = [b'D', b'M', b'D', b'N', 0x80];
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(5));
    assert_eq!(
        parsed.message,
        Some(RemoteMessage::MouseDown { button: 0x80 })
    );
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 5];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::MouseDown { button: 0x80 },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Ok(5)
    );
    assert_eq!(output, payload);
}

#[test]
fn mouse_up_decodes_and_encodes_one_raw_button_id() {
    let payload = [b'D', b'M', b'U', b'P', 0xff];
    let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(5));
    assert_eq!(
        parsed.message,
        Some(RemoteMessage::MouseUp { button: 0xff })
    );
    assert!(!parsed.message.unwrap().is_terminal());

    let mut output = [0xa5; 5];
    assert_eq!(
        encode_remote_message_to(
            RemoteMessage::MouseUp { button: 0xff },
            CLIENT_ACTIVE,
            &mut output,
        ),
        Ok(5)
    );
    assert_eq!(output, payload);
}

#[test]
fn mouse_button_decode_and_encode_preserve_every_u8_value() {
    for button in u8::MIN..=u8::MAX {
        for (code, message) in [
            (*b"DMDN", RemoteMessage::MouseDown { button }),
            (*b"DMUP", RemoteMessage::MouseUp { button }),
        ] {
            let payload = [code[0], code[1], code[2], code[3], button];
            let parsed = parse_remote_message(&payload, CLIENT_ACTIVE);
            assert_eq!(parsed.category, Category::Accepted, "{message:?}");
            assert_eq!(parsed.consumed, Some(5), "{message:?}");
            assert_eq!(parsed.message, Some(message), "{message:?}");

            let mut output = [0xa5; 5];
            assert_eq!(
                encode_remote_message_to(message, CLIENT_ACTIVE, &mut output),
                Ok(5),
                "{message:?}"
            );
            assert_eq!(output, payload, "{message:?}");
        }
    }
}

#[test]
fn mouse_button_context_matrix_is_only_server_to_client_active() {
    for message in [
        RemoteMessage::MouseDown { button: 1 },
        RemoteMessage::MouseUp { button: 1 },
    ] {
        let code = match message {
            RemoteMessage::MouseDown { .. } => *b"DMDN",
            RemoteMessage::MouseUp { .. } => *b"DMUP",
            _ => unreachable!(),
        };
        let payload = [code[0], code[1], code[2], code[3], 1];
        for context in ALL_REMOTE_MESSAGE_CONTEXTS {
            let parsed = parse_remote_message(&payload, context);
            let mut output = [0xa5; 5];
            let before = output;
            let encoded = encode_remote_message_to(message, context, &mut output);
            if context == CLIENT_ACTIVE {
                assert_eq!(parsed.category, Category::Accepted, "{message:?}");
                assert_eq!(parsed.consumed, Some(5), "{message:?}");
                assert_eq!(parsed.message, Some(message), "{message:?}");
                assert_eq!(encoded, Ok(5), "{message:?}");
                assert_eq!(output, payload, "{message:?}");
            } else {
                assert_eq!(
                    parsed.category,
                    Category::Malformed,
                    "{message:?} {context:?}"
                );
                assert_eq!(parsed.consumed, None, "{message:?} {context:?}");
                assert_eq!(parsed.message, None, "{message:?} {context:?}");
                assert_eq!(
                    encoded,
                    Err(RemoteEncodeToError::Encode(
                        RemoteEncodeError::InvalidContext
                    )),
                    "{message:?} {context:?}"
                );
                assert_eq!(output, before, "{message:?} {context:?}");
            }
        }
    }
}

#[test]
fn mouse_button_boundaries_preserve_trailing_commands() {
    let mut payload = b"DMDN\x01DMUP\xffCROP".to_vec();
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.consumed, Some(5));
    assert_eq!(first.message, Some(RemoteMessage::MouseDown { button: 1 }));

    payload.drain(..first.consumed.unwrap());
    let second = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(second.consumed, Some(5));
    assert_eq!(
        second.message,
        Some(RemoteMessage::MouseUp { button: u8::MAX })
    );

    let third = parse_remote_message(&payload[second.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(third.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(third.message, Some(RemoteMessage::ResetOptions));
}

#[test]
fn mouse_button_short_inputs_and_outputs_fail_without_partial_boundaries_or_writes() {
    for payload in [b"DMDN\x01".as_slice(), b"DMUP\x01".as_slice()] {
        for length in 0..payload.len() {
            let parsed = parse_remote_message(&payload[..length], CLIENT_ACTIVE);
            assert_eq!(parsed.category, Category::Malformed, "{payload:?} {length}");
            assert_eq!(parsed.consumed, None, "{payload:?} {length}");
            assert_eq!(parsed.message, None, "{payload:?} {length}");
        }
    }

    for message in [
        RemoteMessage::MouseDown { button: 0 },
        RemoteMessage::MouseUp { button: u8::MAX },
    ] {
        let mut short = [0xa5; 4];
        let before = short;
        assert_eq!(
            encode_remote_message_to(message, CLIENT_ACTIVE, &mut short),
            Err(RemoteEncodeToError::OutputTooSmall {
                required: 5,
                available: 4,
            }),
            "{message:?}"
        );
        assert_eq!(short, before, "{message:?}");

        assert_eq!(
            encode_remote_message(message, CLIENT_ACTIVE),
            Err(RemoteEncodeError::RequiresOutputBuffer),
            "{message:?}"
        );
    }
}

#[test]
fn frozen_cpp_keep_alive_is_decoded_in_client_handshake() {
    let parsed = parse_remote_message(REMOTE_CALV_PAYLOAD, CLIENT_HANDSHAKE);

    assert_eq!(parsed.category, Category::Accepted);
    assert_eq!(parsed.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(parsed.message, Some(RemoteMessage::KeepAlive));
}

#[test]
fn keep_alive_decode_matrix_is_fail_closed_across_all_eight_contexts() {
    let accepted_contexts = [
        CLIENT_HANDSHAKE,
        CLIENT_ACTIVE,
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::Active,
        ),
    ];

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let parsed = parse_remote_message(REMOTE_CALV_PAYLOAD, context);
        if accepted_contexts.contains(&context) {
            assert_eq!(parsed.category, Category::Accepted, "{context:?}");
            assert_eq!(parsed.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
            assert_eq!(parsed.message, Some(RemoteMessage::KeepAlive));
        } else {
            assert_eq!(parsed.category, Category::Malformed, "{context:?}");
            assert_eq!(parsed.consumed, None);
            assert_eq!(parsed.message, None);
        }
    }
}

#[test]
fn keep_alive_encode_matrix_matches_observed_cpp_send_sites() {
    let observed_contexts = [
        CLIENT_ACTIVE,
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::ServerAwaitingInfo,
        ),
        RemoteMessageContext::new(
            RemoteMessageDirection::ClientToServer,
            RemoteMessageState::Active,
        ),
    ];

    for context in ALL_REMOTE_MESSAGE_CONTEXTS {
        let encoded = encode_remote_message(RemoteMessage::KeepAlive, context);
        if observed_contexts.contains(&context) {
            assert_eq!(
                encoded.unwrap().as_slice(),
                REMOTE_CALV_PAYLOAD,
                "{context:?}"
            );
        } else {
            assert_eq!(
                encoded,
                Err(RemoteEncodeError::InvalidContext),
                "{context:?}"
            );
        }
    }
}

#[test]
fn server_awaiting_info_keep_alive_is_encode_only() {
    let context = RemoteMessageContext::new(
        RemoteMessageDirection::ClientToServer,
        RemoteMessageState::ServerAwaitingInfo,
    );

    assert_eq!(
        encode_remote_message(RemoteMessage::KeepAlive, context)
            .unwrap()
            .as_slice(),
        REMOTE_CALV_PAYLOAD
    );
    let decoded = parse_remote_message(REMOTE_CALV_PAYLOAD, context);
    assert_eq!(decoded.category, Category::Malformed);
    assert_eq!(decoded.consumed, None);
    assert_eq!(decoded.message, None);
}

#[test]
fn keep_alive_is_nonterminal_parser_metadata_only() {
    assert!(!RemoteMessage::KeepAlive.is_terminal());
}

#[test]
fn every_short_and_single_byte_corrupted_keep_alive_is_malformed() {
    for length in 0..REMOTE_MESSAGE_CODE_LENGTH {
        let parsed = parse_remote_message(&REMOTE_CALV_PAYLOAD[..length], CLIENT_ACTIVE);
        assert_eq!(
            parsed.category,
            Category::Malformed,
            "short length={length}"
        );
        assert_eq!(parsed.consumed, None);
        assert_eq!(parsed.message, None);
    }

    for byte_index in 0..REMOTE_MESSAGE_CODE_LENGTH {
        let mut corrupted = REMOTE_CALV_PAYLOAD.to_vec();
        corrupted[byte_index] ^= 1;
        let parsed = parse_remote_message(&corrupted, CLIENT_ACTIVE);
        assert_eq!(
            parsed.category,
            Category::Malformed,
            "corrupted byte_index={byte_index}"
        );
        assert_eq!(parsed.consumed, None);
        assert_eq!(parsed.message, None);
    }
}

#[test]
fn keep_alive_then_noop_are_reparsed_in_order() {
    let mut payload = REMOTE_CALV_PAYLOAD.to_vec();
    payload.extend_from_slice(REMOTE_CNOP_PAYLOAD);

    let keep_alive = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(keep_alive.message, Some(RemoteMessage::KeepAlive));
    assert_eq!(keep_alive.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert!(!keep_alive.message.unwrap().is_terminal());

    let noop = parse_remote_message(&payload[keep_alive.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(noop.message, Some(RemoteMessage::Noop));
    assert_eq!(noop.consumed, Some(REMOTE_MESSAGE_CODE_LENGTH));
    assert_eq!(
        keep_alive.consumed.unwrap() + noop.consumed.unwrap(),
        payload.len()
    );
}

#[test]
fn keep_alive_preserves_partial_or_unknown_next_command_for_fail_closed_reparse() {
    for trailing_length in 1..REMOTE_MESSAGE_CODE_LENGTH {
        let mut payload = REMOTE_CALV_PAYLOAD.to_vec();
        payload.extend_from_slice(&REMOTE_CNOP_PAYLOAD[..trailing_length]);
        let first = parse_remote_message(&payload, CLIENT_ACTIVE);
        assert_eq!(first.message, Some(RemoteMessage::KeepAlive));
        let trailing = &payload[first.consumed.unwrap()..];
        assert_eq!(trailing.len(), trailing_length);
        assert_eq!(
            parse_remote_message(trailing, CLIENT_ACTIVE).category,
            Category::Malformed
        );
    }

    let mut unknown = REMOTE_CALV_PAYLOAD.to_vec();
    unknown[0] ^= 1;
    let mut payload = REMOTE_CALV_PAYLOAD.to_vec();
    payload.extend_from_slice(&unknown);
    let first = parse_remote_message(&payload, CLIENT_ACTIVE);
    assert_eq!(first.message, Some(RemoteMessage::KeepAlive));
    let rejected = parse_remote_message(&payload[first.consumed.unwrap()..], CLIENT_ACTIVE);
    assert_eq!(rejected.category, Category::Malformed);
    assert_eq!(rejected.consumed, None);
    assert_eq!(rejected.message, None);
}

#[test]
fn client_session_accepts_fragmented_hello_then_decodes_command() {
    let mut session = ClientSession::new();
    let split = REMOTE_HELLO_1_6.len() / 2;
    let partial = session.receive(&REMOTE_HELLO_1_6[..split]);
    assert_eq!(partial.category, Category::NeedMore);
    assert_eq!(partial.event, None);

    let hello = session.receive(&REMOTE_HELLO_1_6[split..]);
    assert_eq!(session.state(), ClientSessionState::Active);
    assert_eq!(
        hello.event,
        Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
    );

    let mut frame = vec![0, 0, 0, 4];
    frame.extend_from_slice(b"CNOP");
    let command = session.receive(&frame);
    assert_eq!(command.category, Category::Accepted);
    assert_eq!(
        command.event,
        Some(ClientSessionEvent::Message(RemoteMessage::Noop))
    );
}

#[test]
fn client_session_retains_coalesced_command_and_closes_on_terminal() {
    let mut session = ClientSession::new();
    let mut hello_and_command = REMOTE_HELLO_1_6.to_vec();
    hello_and_command.extend_from_slice(&[0, 0, 0, 4]);
    hello_and_command.extend_from_slice(b"CNOP");
    let hello = session.receive(&hello_and_command);
    assert_eq!(
        hello.event,
        Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
    );

    let command = session.receive(&[]);
    assert_eq!(
        command.event,
        Some(ClientSessionEvent::Message(RemoteMessage::Noop))
    );

    let mut close_frame = vec![0, 0, 0, 4];
    close_frame.extend_from_slice(b"CBYE");
    let close = session.receive(&close_frame);
    assert_eq!(
        close.event,
        Some(ClientSessionEvent::Message(RemoteMessage::Close))
    );
    assert_eq!(session.state(), ClientSessionState::Closed);
}

#[test]
fn server_session_accepts_dinf_and_enters_active_state() {
    let mut session = ServerSession::new();
    let hello = b"Barrier\x00\x01\x00\x06\x00\x00\x00\x0akat-client";
    let mut input = vec![0, 0, 0, 25];
    input.extend_from_slice(hello);
    input.extend_from_slice(&[0, 0, 0, 18]);
    input.extend_from_slice(b"DINF");
    for value in [10i16, 20, 1920, 1080, 0, 300, 400] {
        input.extend_from_slice(&value.to_be_bytes());
    }

    let handshake = session.receive(&input);
    assert_eq!(
        handshake.event,
        Some(ServerSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
    );

    let info = session.receive(&[]);
    assert_eq!(
        info.event,
        Some(ServerSessionEvent::Message(RemoteMessage::DeviceInfo {
            x: 10,
            y: 20,
            width: 1920,
            height: 1080,
            dummy: 0,
            mouse_x: 300,
            mouse_y: 400,
        }))
    );
    assert_eq!(session.state(), ServerSessionState::Active);
}
