//! Media state machine — processes commands from Python.

use crate::{
    audio, codec, push_event, push_video_frame, quic, video, EventQueue, MediaCommand,
    MediaEvent, VideoFrameOutput, VideoFrameQueue,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Maximum number of automatic reconnection attempts after a QUIC read error.
const MAX_RECONNECT_ATTEMPTS: u32 = 5;
/// Maximum backoff delay in seconds between reconnection attempts.
const MAX_BACKOFF_SECS: u64 = 30;
/// Evict idle per-user video decoders after this duration.
const DECODER_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Evict stale partial video frames after this duration.
const REASSEMBLY_STALE_TIMEOUT: Duration = Duration::from_secs(2);
/// RMS threshold (normalized 0.0–1.0) above which a user is considered speaking.
const SPEAKING_THRESHOLD: f64 = 0.01;
/// How long after the last above-threshold frame before emitting speaking_stop.
const SPEAKING_HOLDOFF: Duration = Duration::from_millis(200);

/// Snapshot of connection parameters for automatic reconnection.
#[derive(Clone)]
struct ConnectParams {
    url: String,
    token: String,
    room_id: u32,
    user_id: u32,
    cert_der: Option<Vec<u8>>,
    idle_timeout_secs: u64,
    datagram_buffer_size: usize,
}

/// Video configuration (set before enabling video).
#[derive(Clone)]
struct VideoConfig {
    width: u32,
    height: u32,
    fps: u32,
    bitrate_kbps: u32,
}

impl Default for VideoConfig {
    fn default() -> Self {
        VideoConfig {
            width: 640,
            height: 480,
            fps: 30,
            bitrate_kbps: 500,
        }
    }
}

/// Per-user speaking state for hysteresis-based detection.
struct SpeakingState {
    speaking: bool,
    last_above_threshold: Instant,
}

/// Per-user audio decoder with idle tracking.
struct UserAudioDecoder {
    decoder: codec::OpusDecoder,
    last_used: Instant,
}

/// Per-user video decoder with idle tracking.
struct UserVideoDecoder {
    decoder: codec::Av1Decoder,
    last_used: Instant,
}

/// Active media session — all live resources.
/// Dropping this struct tears down the QUIC connection, stops audio streams,
/// and frees the Opus encoder/decoder automatically.
struct ActiveSession {
    connection: quinn::Connection,
    room_id: u32,
    user_id: u32,
    // Audio state
    sequence: u32,
    timestamp: u32,
    encoder: codec::OpusEncoder,
    audio_decoders: HashMap<u32, UserAudioDecoder>,
    _capture_stream: cpal::Stream,
    capture_rx: mpsc::UnboundedReceiver<Vec<i16>>,
    _playback_stream: cpal::Stream,
    playback_tx: mpsc::UnboundedSender<Vec<i16>>,
    muted: bool,
    deafened: bool,
    // Volume / noise gate
    input_volume: f32,
    output_volume: f32,
    noise_gate_threshold: f32,
    user_volumes: HashMap<u32, f32>,
    // Speaking detection
    speaking_states: HashMap<u32, SpeakingState>,
    // Video state
    video: bool,
    video_config: VideoConfig,
    video_sequence: u32,
    video_timestamp: u32,
    video_encoder: Option<codec::Av1Encoder>,
    video_decoders: HashMap<u32, UserVideoDecoder>,
    video_reassembler: quic::VideoReassembler,
    camera_rx: Option<mpsc::Receiver<video::CapturedFrame>>,
    camera_stop: Option<video::CameraStopHandle>,
    video_frame_queue: VideoFrameQueue,
}

/// Establish a QUIC connection and start the audio pipeline.
async fn establish_session(
    url: String,
    token: String,
    room_id: u32,
    user_id: u32,
    cert_der: Option<Vec<u8>>,
    idle_timeout_secs: u64,
    datagram_buffer_size: usize,
    video_frame_queue: VideoFrameQueue,
) -> Result<ActiveSession, Box<dyn std::error::Error>> {
    // Parse URL — strip optional quic:// prefix
    let addr_str = url
        .strip_prefix("quic://")
        .unwrap_or(&url);

    // Try to split host:port, preserving the hostname for TLS SNI
    let (host, addr) = if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        (sa.ip().to_string(), sa)
    } else {
        let colon = addr_str.rfind(':').ok_or("missing port in URL")?;
        let hostname = &addr_str[..colon];
        let port: u16 = addr_str[colon + 1..].parse()?;
        let resolved = tokio::net::lookup_host((hostname, port)).await?
            .next().ok_or("DNS resolution failed")?;
        (hostname.to_string(), resolved)
    };

    // Create QUIC endpoint and connect
    let mut client_config = quic::make_client_config(cert_der)?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(idle_timeout_secs))
            .map_err(|e| format!("Invalid idle timeout: {e}"))?,
    ));
    transport.datagram_receive_buffer_size(Some(datagram_buffer_size));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint.connect(addr, &host)?.await?;

    // Send auth token as first datagram (SFU protocol requirement)
    connection.send_datagram(Bytes::from(token))?;

    // Start audio capture (960 samples = 20ms at 48kHz)
    let (capture_stream, capture_rx) = audio::start_capture(960)?;

    // Start audio playback
    let (playback_stream, playback_tx) = audio::start_playback()?;

    // Create Opus encoder
    let encoder = codec::OpusEncoder::new()?;

    Ok(ActiveSession {
        connection,
        room_id,
        user_id,
        sequence: 0,
        timestamp: 0,
        encoder,
        audio_decoders: HashMap::new(),
        _capture_stream: capture_stream,
        capture_rx,
        _playback_stream: playback_stream,
        playback_tx,
        muted: false,
        deafened: false,
        input_volume: 1.0,
        output_volume: 1.0,
        noise_gate_threshold: 0.0,
        user_volumes: HashMap::new(),
        speaking_states: HashMap::new(),
        video: false,
        video_config: VideoConfig::default(),
        video_sequence: 0,
        video_timestamp: 0,
        video_encoder: None,
        video_decoders: HashMap::new(),
        video_reassembler: quic::VideoReassembler::new(),
        camera_rx: None,
        camera_stop: None,
        video_frame_queue,
    })
}

/// Attempt to reconnect with exponential backoff.
async fn reconnect_with_backoff(
    params: &ConnectParams,
    events: &EventQueue,
    video_frames: &VideoFrameQueue,
) -> Option<ActiveSession> {
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        let delay_secs = std::cmp::min(2u64.pow(attempt - 1), MAX_BACKOFF_SECS);
        push_event(events, MediaEvent::Reconnecting { attempt, delay_secs });
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;

        tracing::info!("Reconnect attempt {}/{}", attempt, MAX_RECONNECT_ATTEMPTS);
        match establish_session(
            params.url.clone(),
            params.token.clone(),
            params.room_id,
            params.user_id,
            params.cert_der.clone(),
            params.idle_timeout_secs,
            params.datagram_buffer_size,
            video_frames.clone(),
        ).await {
            Ok(s) => {
                push_event(events, MediaEvent::Connected);
                return Some(s);
            }
            Err(e) => {
                tracing::warn!("Reconnect attempt {} failed: {}", attempt, e);
            }
        }
    }

    push_event(
        events,
        MediaEvent::Disconnected(format!(
            "Reconnection failed after {} attempts",
            MAX_RECONNECT_ATTEMPTS
        )),
    );
    None
}

/// Main media event loop. Receives commands from the Python layer
/// and manages QUIC connection + audio/video pipeline lifecycle.
pub async fn run_media_loop(
    mut cmd_rx: mpsc::UnboundedReceiver<MediaCommand>,
    cancel: CancellationToken,
    events: EventQueue,
    video_frames: VideoFrameQueue,
) {
    let mut session: Option<ActiveSession> = None;
    let mut last_connect_params: Option<ConnectParams> = None;

    loop {
        match &mut session {
            None => {
                // Disconnected — only listen for commands and cancellation
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Media loop cancelled");
                        break;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            None => break,
                            Some(MediaCommand::Connect { url, token, room_id, user_id, cert_der, idle_timeout_secs, datagram_buffer_size }) => {
                                tracing::info!("Connecting to SFU at {}", url);
                                let params = ConnectParams {
                                    url: url.clone(),
                                    token: token.clone(),
                                    room_id,
                                    user_id,
                                    cert_der: cert_der.clone(),
                                    idle_timeout_secs,
                                    datagram_buffer_size,
                                };
                                match establish_session(url, token, room_id, user_id, cert_der, idle_timeout_secs, datagram_buffer_size, video_frames.clone()).await {
                                    Ok(s) => {
                                        tracing::info!("Connected to SFU");
                                        push_event(&events, MediaEvent::Connected);
                                        last_connect_params = Some(params);
                                        session = Some(s);
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to connect to SFU: {}", e);
                                        push_event(&events, MediaEvent::ConnectFailed(e.to_string()));
                                    }
                                }
                            }
                            Some(MediaCommand::Disconnect) => {}
                            Some(MediaCommand::SetMute(_)) => {}
                            Some(MediaCommand::SetDeaf(_)) => {}
                            Some(MediaCommand::SetVideo(_)) => {}
                            Some(MediaCommand::SetVideoConfig { .. }) => {}
                            Some(MediaCommand::SetInputVolume(_)) => {}
                            Some(MediaCommand::SetOutputVolume(_)) => {}
                            Some(MediaCommand::SetNoiseGate(_)) => {}
                            Some(MediaCommand::SetUserVolume { .. }) => {}
                        }
                    }
                }
            }
            Some(s) => {
                // Connected — listen for commands, capture frames, and incoming datagrams.
                // We need to conditionally poll the camera receiver.
                let camera_frame = async {
                    match &mut s.camera_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                };

                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Media loop cancelled");
                        break;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            None => break,
                            Some(MediaCommand::Connect { url, token, room_id, user_id, cert_der, idle_timeout_secs, datagram_buffer_size }) => {
                                tracing::info!("Reconnecting to SFU at {}", url);
                                session = None;
                                let params = ConnectParams {
                                    url: url.clone(),
                                    token: token.clone(),
                                    room_id,
                                    user_id,
                                    cert_der: cert_der.clone(),
                                    idle_timeout_secs,
                                    datagram_buffer_size,
                                };
                                match establish_session(url, token, room_id, user_id, cert_der, idle_timeout_secs, datagram_buffer_size, video_frames.clone()).await {
                                    Ok(new_s) => {
                                        tracing::info!("Connected to SFU");
                                        push_event(&events, MediaEvent::Connected);
                                        last_connect_params = Some(params);
                                        session = Some(new_s);
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to connect to SFU: {}", e);
                                        push_event(&events, MediaEvent::ConnectFailed(e.to_string()));
                                    }
                                }
                                continue;
                            }
                            Some(MediaCommand::Disconnect) => {
                                tracing::info!("Disconnecting from SFU");
                                push_event(&events, MediaEvent::Disconnected("user requested".into()));
                                last_connect_params = None;
                                session = None;
                                continue;
                            }
                            Some(MediaCommand::SetMute(muted)) => {
                                s.muted = muted;
                            }
                            Some(MediaCommand::SetDeaf(deafened)) => {
                                s.deafened = deafened;
                            }
                            Some(MediaCommand::SetVideo(enabled)) => {
                                handle_set_video(s, enabled, &events);
                            }
                            Some(MediaCommand::SetVideoConfig { width, height, fps, bitrate_kbps }) => {
                                s.video_config = VideoConfig { width, height, fps, bitrate_kbps };
                            }
                            Some(MediaCommand::SetInputVolume(v)) => {
                                s.input_volume = v;
                            }
                            Some(MediaCommand::SetOutputVolume(v)) => {
                                s.output_volume = v;
                            }
                            Some(MediaCommand::SetNoiseGate(t)) => {
                                s.noise_gate_threshold = t;
                            }
                            Some(MediaCommand::SetUserVolume { user_id, volume }) => {
                                if (volume - 1.0).abs() < f32::EPSILON {
                                    s.user_volumes.remove(&user_id);
                                } else {
                                    s.user_volumes.insert(user_id, volume);
                                }
                            }
                        }
                    }
                    Some(mut pcm) = s.capture_rx.recv() => {
                        if !s.muted {
                            apply_input_processing(&mut pcm, s.input_volume, s.noise_gate_threshold);
                            // Speaking detection on processed local audio
                            update_speaking_state(s, s.user_id, &pcm, &events);
                            send_audio_frame(s, pcm);
                        } else {
                            // Muted → ensure we stop speaking
                            let state = s.speaking_states.get(&s.user_id);
                            if state.is_some_and(|st| st.speaking) {
                                if let Some(st) = s.speaking_states.get_mut(&s.user_id) {
                                    st.speaking = false;
                                }
                                push_event(&events, MediaEvent::SpeakingStop(s.user_id));
                            }
                        }
                    }
                    Some(frame) = camera_frame => {
                        handle_camera_frame(s, frame, &events);
                    }
                    result = s.connection.read_datagram() => {
                        match result {
                            Ok(data) => {
                                receive_datagram(s, data, &events);
                            }
                            Err(e) => {
                                tracing::error!("QUIC read error: {}", e);
                                session = None;

                                if let Some(ref params) = last_connect_params {
                                    if let Some(new_session) = reconnect_with_backoff(params, &events, &video_frames).await {
                                        session = Some(new_session);
                                    } else {
                                        last_connect_params = None;
                                    }
                                } else {
                                    push_event(&events, MediaEvent::Disconnected(e.to_string()));
                                }
                                continue;
                            }
                        }
                    }
                }

                // Periodic cleanup: evict stale reassembly entries and idle decoders
                if let Some(s) = &mut session {
                    s.video_reassembler.evict_stale(REASSEMBLY_STALE_TIMEOUT);
                    evict_idle_decoders(s);
                }
            }
        }
    }
}

/// Handle SetVideo command: start/stop camera + encoder.
fn handle_set_video(session: &mut ActiveSession, enabled: bool, events: &EventQueue) {
    if enabled == session.video {
        return;
    }

    if enabled {
        let cfg = video::CameraConfig {
            width: session.video_config.width,
            height: session.video_config.height,
            fps: session.video_config.fps,
        };

        match video::start_camera_capture(cfg) {
            Ok((rx, stop)) => {
                session.camera_rx = Some(rx);
                session.camera_stop = Some(stop);
            }
            Err(e) => {
                push_event(events, MediaEvent::VideoError(format!("Camera start failed: {e}")));
                return;
            }
        }

        match codec::Av1Encoder::new(
            session.video_config.width as usize,
            session.video_config.height as usize,
            session.video_config.fps,
            session.video_config.bitrate_kbps,
        ) {
            Ok(enc) => {
                session.video_encoder = Some(enc);
            }
            Err(e) => {
                // Stop camera if encoder fails
                session.camera_rx = None;
                session.camera_stop = None;
                push_event(events, MediaEvent::VideoError(format!("AV1 encoder init failed: {e}")));
                return;
            }
        }

        session.video = true;
        session.video_sequence = 0;
        session.video_timestamp = 0;
        tracing::info!("Video enabled");
    } else {
        // Stop camera and drop encoder
        session.camera_rx = None;
        session.camera_stop = None;
        session.video_encoder = None;
        session.video = false;
        tracing::info!("Video disabled");
    }
}

/// Process a captured camera frame: push local preview + encode + send.
fn handle_camera_frame(
    session: &mut ActiveSession,
    frame: video::CapturedFrame,
    events: &EventQueue,
) {
    // Push local preview (user_id = 0)
    push_video_frame(&session.video_frame_queue, VideoFrameOutput {
        user_id: 0,
        width: frame.width,
        height: frame.height,
        rgba: frame.rgba,
    });

    // Encode and send
    let encoder = match &mut session.video_encoder {
        Some(enc) => enc,
        None => return,
    };

    let packets = match encoder.encode(&frame.y, &frame.u, &frame.v) {
        Ok(pkts) => pkts,
        Err(e) => {
            tracing::warn!("AV1 encode error: {e}");
            push_event(events, MediaEvent::VideoError(format!("AV1 encode: {e}")));
            return;
        }
    };

    for pkt in packets {
        let ts = session.video_timestamp;
        if let Err(e) = quic::send_video_fragmented(
            &session.connection,
            session.room_id,
            session.user_id,
            &mut session.video_sequence,
            ts,
            pkt.is_keyframe,
            &pkt.data,
        ) {
            tracing::warn!("Failed to send video: {e}");
        }
        session.video_timestamp = session.video_timestamp.wrapping_add(1);
    }
}

/// Dispatch an incoming datagram based on media type.
fn receive_datagram(session: &mut ActiveSession, data: Bytes, events: &EventQueue) {
    let frame = match quic::InFrame::decode(data) {
        Some(f) => f,
        None => {
            tracing::trace!("Unparseable incoming datagram, ignoring");
            return;
        }
    };

    match frame.header.media_type {
        quic::MEDIA_TYPE_AUDIO => {
            if !session.deafened {
                receive_audio_frame(session, frame, events);
            }
        }
        quic::MEDIA_TYPE_VIDEO => {
            receive_video_fragment(session, frame, events);
        }
        _ => {
            tracing::trace!("Ignoring media_type={}", frame.header.media_type);
        }
    }
}

/// Encode and send an audio frame over QUIC.
fn send_audio_frame(session: &mut ActiveSession, pcm: Vec<i16>) {
    let (opus_data, is_dtx) = match session.encoder.encode(&pcm) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("Opus encode error: {}", e);
            return;
        }
    };

    let mut frame = quic::OutFrame::audio(
        session.room_id,
        session.user_id,
        quic::CODEC_OPUS,
        session.sequence,
        session.timestamp,
        opus_data,
    );
    frame.header.dtx = is_dtx;

    if let Err(e) = session.connection.send_datagram(frame.encode()) {
        tracing::warn!("Failed to send datagram: {}", e);
    }

    session.sequence = session.sequence.wrapping_add(1);
    session.timestamp = session.timestamp.wrapping_add(960);
}

/// Update speaking state for a user based on PCM audio levels.
/// Emits SpeakingStart/SpeakingStop events with hysteresis.
fn update_speaking_state(session: &mut ActiveSession, user_id: u32, pcm: &[i16], events: &EventQueue) {
    if pcm.is_empty() {
        return;
    }
    let rms = (pcm.iter().map(|&s| (s as f64).powi(2)).sum::<f64>() / pcm.len() as f64).sqrt();
    let normalized_rms = rms / 32767.0;
    let now = Instant::now();

    let state = session.speaking_states.entry(user_id).or_insert(SpeakingState {
        speaking: false,
        last_above_threshold: now - SPEAKING_HOLDOFF - Duration::from_millis(1),
    });

    if normalized_rms >= SPEAKING_THRESHOLD {
        state.last_above_threshold = now;
        if !state.speaking {
            state.speaking = true;
            push_event(events, MediaEvent::SpeakingStart(user_id));
        }
    } else if state.speaking && now.duration_since(state.last_above_threshold) >= SPEAKING_HOLDOFF {
        state.speaking = false;
        push_event(events, MediaEvent::SpeakingStop(user_id));
    }
}

/// Decode and play back a received audio frame with per-user decoder and volume scaling.
fn receive_audio_frame(session: &mut ActiveSession, frame: quic::InFrame, events: &EventQueue) {
    let user_id = frame.header.user_id;

    let user_decoder = session
        .audio_decoders
        .entry(user_id)
        .or_insert_with(|| UserAudioDecoder {
            decoder: codec::OpusDecoder::new().expect("opus decoder"),
            last_used: Instant::now(),
        });
    user_decoder.last_used = Instant::now();

    let mut pcm = match user_decoder.decoder.decode(&frame.payload) {
        Ok(samples) => samples,
        Err(e) => {
            tracing::warn!("Opus decode error for user {}: {}", user_id, e);
            return;
        }
    };

    // Speaking detection on decoded PCM (before volume scaling)
    update_speaking_state(session, user_id, &pcm, events);

    // Apply per-user volume and global output volume
    let user_vol = session.user_volumes.get(&user_id).copied().unwrap_or(1.0);
    let combined_vol = user_vol * session.output_volume;

    if (combined_vol - 1.0).abs() > f32::EPSILON {
        for s in pcm.iter_mut() {
            *s = ((*s as f32) * combined_vol).clamp(-32767.0, 32767.0) as i16;
        }
    }

    let _ = session.playback_tx.send(pcm);
}

/// Process a received video fragment: reassemble → decode → push to queue.
fn receive_video_fragment(
    session: &mut ActiveSession,
    frame: quic::InFrame,
    _events: &EventQueue,
) {
    let reassembled = match session
        .video_reassembler
        .add_fragment(&frame.header, &frame.payload)
    {
        Some(r) => r,
        None => return, // Still collecting fragments
    };

    // Get or create per-user decoder
    let user_decoder = session
        .video_decoders
        .entry(reassembled.user_id)
        .or_insert_with(|| {
            let decoder = codec::Av1Decoder::new().unwrap_or_else(|e| {
                tracing::error!("Failed to create AV1 decoder for user {}: {e}", reassembled.user_id);
                // Return a decoder that will likely fail — but we log the error
                // This branch shouldn't realistically happen.
                panic!("dav1d init failed: {e}");
            });
            UserVideoDecoder {
                decoder,
                last_used: Instant::now(),
            }
        });
    user_decoder.last_used = Instant::now();

    match user_decoder.decoder.decode(&reassembled.data) {
        Ok(Some(decoded)) => {
            push_video_frame(
                &session.video_frame_queue,
                VideoFrameOutput {
                    user_id: reassembled.user_id,
                    width: decoded.width,
                    height: decoded.height,
                    rgba: decoded.rgba,
                },
            );
        }
        Ok(None) => {
            // Decoder needs more data
        }
        Err(e) => {
            tracing::warn!("AV1 decode error for user {}: {e}", reassembled.user_id);
        }
    }
}

/// Apply noise gate and input volume scaling to a PCM buffer.
fn apply_input_processing(pcm: &mut Vec<i16>, volume: f32, gate_threshold: f32) {
    // Noise gate (RMS-based)
    if gate_threshold > 0.0 {
        let rms = (pcm.iter().map(|&s| (s as f64).powi(2)).sum::<f64>() / pcm.len() as f64).sqrt();
        let normalized_rms = rms / 32767.0;
        if normalized_rms < gate_threshold as f64 {
            pcm.fill(0);
            return;
        }
    }
    // Volume scaling
    if (volume - 1.0).abs() > f32::EPSILON {
        for s in pcm.iter_mut() {
            *s = ((*s as f32) * volume).clamp(-32767.0, 32767.0) as i16;
        }
    }
}

/// Evict per-user audio and video decoders that have been idle too long.
fn evict_idle_decoders(session: &mut ActiveSession) {
    let now = Instant::now();
    session
        .audio_decoders
        .retain(|uid, dec| {
            let keep = now.duration_since(dec.last_used) < DECODER_IDLE_TIMEOUT;
            if !keep {
                tracing::debug!("Evicting idle audio decoder for user {uid}");
            }
            keep
        });
    session
        .video_decoders
        .retain(|uid, dec| {
            let keep = now.duration_since(dec.last_used) < DECODER_IDLE_TIMEOUT;
            if !keep {
                tracing::debug!("Evicting idle video decoder for user {uid}");
            }
            keep
        });
}
