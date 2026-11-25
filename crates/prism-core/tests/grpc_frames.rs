use bytes::BytesMut;
use prism_core::outbound::transport::{gun_message, gun_take};

#[test]
fn rejects_oversized_declarations_and_unnegotiated_compression_before_body() {
    for flag in [1, 2, 255] {
        assert!(gun_take(&mut BytesMut::from(&[flag, 0, 0, 0, 0][..])).is_err());
    }
    for size in [4 * 1024 * 1024 + 1, u32::MAX] {
        let mut header = BytesMut::from(&[0][..]);
        header.extend_from_slice(&size.to_be_bytes());
        assert!(gun_take(&mut header).is_err());
    }
    let mut at_limit = BytesMut::from(&[0, 0, 64, 0, 0][..]);
    assert!(gun_take(&mut at_limit).unwrap().is_empty());
    assert_eq!(at_limit.len(), 5);
}

#[test]
fn rejects_unterminated_overflowing_and_short_hunk_lengths() {
    for proto in [
        vec![0x0a],
        vec![0x0a, 0x80],
        vec![0x0a, 0x80, 0x80, 0x80, 0x80, 0x10],
        vec![0x0a, 2, b'x'],
    ] {
        let mut frame = BytesMut::from(&[0][..]);
        frame.extend_from_slice(&(proto.len() as u32).to_be_bytes());
        frame.extend_from_slice(&proto);
        assert!(gun_take(&mut frame).is_err(), "accepted {proto:?}");
    }
}

#[test]
fn preserves_fragmented_and_coalesced_payloads() {
    let payload: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let mut wire = gun_message(&payload);
    wire.extend_from_slice(&gun_message(b""));
    wire.extend_from_slice(&gun_message(b"tail"));
    let mut pending = BytesMut::new();
    let mut messages = Vec::new();
    for chunk in wire.chunks(137) {
        pending.extend_from_slice(chunk);
        messages.extend(gun_take(&mut pending).unwrap());
    }
    assert!(pending.is_empty());
    assert_eq!(messages.len(), 3);
    assert_eq!(&messages[0][..], payload.as_slice());
    assert!(messages[1].is_empty());
    assert_eq!(&messages[2][..], b"tail");
}

#[tokio::test]
async fn live_http2_peer_cannot_hold_client_waiting_for_invalid_body() {
    use bytes::Bytes;
    use prism_core::outbound::transport::Transport;
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    for header in [[0, 0xff, 0xff, 0xff, 0xff], [1, 0, 0, 0, 1]] {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (ready, sent) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/PrismFrameTest/Tun");
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            stream
                .send_data(Bytes::copy_from_slice(&header), false)
                .unwrap();
            ready.send(()).unwrap();
            // Keep the HTTP/2 connection and response body open: rejection must
            // follow the invalid header, not a peer EOF or receipt of the body.
            while connection.accept().await.is_some() {}
        });
        let mut stream = Transport::Grpc {
            service: "PrismFrameTest".into(),
        }
        .wrap(Box::new(client), "fixture.test")
        .await
        .unwrap();
        timeout(Duration::from_secs(2), sent)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        let received = timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
        peer.abort();
        assert_eq!(
            received
                .expect("invalid header must close promptly")
                .unwrap(),
            0
        );
    }
}
