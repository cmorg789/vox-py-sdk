//! cpal audio capture and playback.
//!
//! Negotiates the best supported device config (targeting 48 kHz mono)
//! and resamples on-the-fly when the hardware rate differs.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::SupportedStreamConfigRange;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Captured audio samples from the microphone.
pub type AudioSamples = Vec<i16>;

/// Target sample rate for the Opus codec pipeline.
const TARGET_RATE: u32 = 48_000;
/// Target channel count.
const TARGET_CHANNELS: u16 = 1;

// ---------------------------------------------------------------------------
// Config negotiation
// ---------------------------------------------------------------------------

/// Chosen device configuration after negotiation.
struct NegotiatedConfig {
    /// The stream config to pass to cpal.
    stream: cpal::StreamConfig,
    /// Whether we need to resample (device rate != 48 kHz).
    needs_resample: bool,
    /// The device's native sample rate.
    device_rate: u32,
    /// The device's native channel count.
    device_channels: u16,
}

/// Pick the best supported config for a device, targeting 48 kHz mono.
///
/// Priority:
/// 1. Exact match: 48 kHz, 1 channel
/// 2. 48 kHz with any channel count (we down-mix)
/// 3. Closest rate that is a multiple/factor of 48 kHz, mono preferred
/// 4. Any supported config (we resample + channel convert)
fn negotiate_config(
    configs: impl Iterator<Item = SupportedStreamConfigRange>,
) -> Result<NegotiatedConfig, Box<dyn std::error::Error>> {
    let ranges: Vec<SupportedStreamConfigRange> = configs.collect();
    if ranges.is_empty() {
        return Err("Device reports no supported configurations".into());
    }

    // Check if a range includes our target rate
    let supports_48k = |r: &SupportedStreamConfigRange| -> bool {
        r.min_sample_rate() <= TARGET_RATE
            && r.max_sample_rate() >= TARGET_RATE
    };

    // 1. Exact match: 48 kHz and mono
    if let Some(r) = ranges
        .iter()
        .find(|r| supports_48k(r) && r.channels() == TARGET_CHANNELS)
    {
        let cfg = r.with_sample_rate(TARGET_RATE);
        return Ok(NegotiatedConfig {
            stream: cfg.into(),
            needs_resample: false,
            device_rate: TARGET_RATE,
            device_channels: TARGET_CHANNELS,
        });
    }

    // 2. 48 kHz with any channel count (we'll down-mix in the callback)
    if let Some(r) = ranges.iter().find(|r| supports_48k(r)) {
        let ch = r.channels();
        let cfg = r.with_sample_rate(TARGET_RATE);
        return Ok(NegotiatedConfig {
            stream: cfg.into(),
            needs_resample: false,
            device_rate: TARGET_RATE,
            device_channels: ch,
        });
    }

    // 3. Preferred alternative rates (multiples / factors of 48 kHz)
    let preferred_rates: &[u32] = &[96_000, 44_100, 24_000, 16_000, 8_000];
    for &rate in preferred_rates {
        // Prefer mono first, then any channel count
        for want_mono in [true, false] {
            if let Some(r) = ranges.iter().find(|r| {
                r.min_sample_rate() <= rate
                    && r.max_sample_rate() >= rate
                    && (!want_mono || r.channels() == TARGET_CHANNELS)
            }) {
                let ch = r.channels();
                let cfg = r.with_sample_rate(rate);
                return Ok(NegotiatedConfig {
                    stream: cfg.into(),
                    needs_resample: true,
                    device_rate: rate,
                    device_channels: ch,
                });
            }
        }
    }

    // 4. Fallback: use the device's default/max config from the first range
    let r = &ranges[0];
    let rate = r.max_sample_rate().min(96_000).max(r.min_sample_rate());
    let ch = r.channels();
    let cfg = r.with_sample_rate(rate);
    Ok(NegotiatedConfig {
        stream: cfg.into(),
        needs_resample: rate != TARGET_RATE,
        device_rate: rate,
        device_channels: ch,
    })
}

// ---------------------------------------------------------------------------
// Linear resampler (capture: device rate → 48 kHz)
// ---------------------------------------------------------------------------

/// Simple linear-interpolation resampler from `from_rate` to `to_rate`.
struct LinearResampler {
    from_rate: u32,
    to_rate: u32,
    /// Fractional position in the source stream.
    phase: f64,
    /// Last source sample (for interpolation).
    prev: f64,
}

impl LinearResampler {
    fn new(from_rate: u32, to_rate: u32) -> Self {
        Self {
            from_rate,
            to_rate,
            phase: 0.0,
            prev: 0.0,
        }
    }

    /// Resample a mono i16 buffer. Returns the resampled output.
    fn process(&mut self, input: &[i16]) -> Vec<i16> {
        if input.is_empty() {
            return Vec::new();
        }
        let ratio = self.from_rate as f64 / self.to_rate as f64;
        let est_len = ((input.len() as f64) / ratio).ceil() as usize + 1;
        let mut out = Vec::with_capacity(est_len);

        for &s in input {
            let cur = s as f64;
            // Emit output samples while our phase is behind the current input sample
            while self.phase < 1.0 {
                let interp = self.prev + (cur - self.prev) * self.phase;
                out.push(interp.clamp(-32767.0, 32767.0) as i16);
                self.phase += ratio;
            }
            self.phase -= 1.0;
            self.prev = cur;
        }
        out
    }
}

/// Resample from 48 kHz to device rate for playback.
struct PlaybackResampler {
    from_rate: u32,
    to_rate: u32,
    phase: f64,
    prev: f64,
}

impl PlaybackResampler {
    fn new(to_rate: u32) -> Self {
        Self {
            from_rate: TARGET_RATE,
            to_rate,
            phase: 0.0,
            prev: 0.0,
        }
    }

    /// Resample mono i16 from 48 kHz → device rate.
    fn process(&mut self, input: &[i16]) -> Vec<i16> {
        if input.is_empty() {
            return Vec::new();
        }
        let ratio = self.from_rate as f64 / self.to_rate as f64;
        let est_len = ((input.len() as f64) / ratio).ceil() as usize + 1;
        let mut out = Vec::with_capacity(est_len);

        for &s in input {
            let cur = s as f64;
            while self.phase < 1.0 {
                let interp = self.prev + (cur - self.prev) * self.phase;
                out.push(interp.clamp(-32767.0, 32767.0) as i16);
                self.phase += ratio;
            }
            self.phase -= 1.0;
            self.prev = cur;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Channel conversion helpers
// ---------------------------------------------------------------------------

/// Down-mix interleaved multi-channel f32 samples to mono i16.
fn downmix_to_mono_i16(data: &[f32], channels: u16) -> Vec<i16> {
    let ch = channels as usize;
    data.chunks_exact(ch)
        .map(|frame| {
            let sum: f32 = frame.iter().sum();
            let avg = sum / ch as f32;
            (avg * 32767.0).clamp(-32767.0, 32767.0) as i16
        })
        .collect()
}

/// Up-mix mono i16 to interleaved multi-channel f32.
fn upmix_from_mono_f32(mono: &[i16], channels: u16) -> Vec<f32> {
    let ch = channels as usize;
    let mut out = Vec::with_capacity(mono.len() * ch);
    for &s in mono {
        let f = s as f32 / 32767.0;
        for _ in 0..ch {
            out.push(f);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Get the human-readable name from a cpal device via its description.
fn device_display_name(device: &cpal::Device) -> String {
    device
        .description()
        .map_or_else(|_| "<unknown>".into(), |d| d.name().to_string())
}

/// Find an input device by name, falling back to the default if not found.
fn find_input_device(
    host: &cpal::Host,
    device_name: Option<&str>,
) -> Result<cpal::Device, Box<dyn std::error::Error>> {
    if let Some(name) = device_name {
        if let Ok(devices) = host.input_devices() {
            for dev in devices {
                if device_display_name(&dev) == name {
                    tracing::info!("Found requested input device: {}", name);
                    return Ok(dev);
                }
            }
        }
        tracing::warn!(
            "Requested input device {:?} not found, falling back to default",
            name
        );
    }
    host.default_input_device()
        .ok_or_else(|| "No input device available".into())
}

/// Find an output device by name, falling back to the default if not found.
fn find_output_device(
    host: &cpal::Host,
    device_name: Option<&str>,
) -> Result<cpal::Device, Box<dyn std::error::Error>> {
    if let Some(name) = device_name {
        if let Ok(devices) = host.output_devices() {
            for dev in devices {
                if device_display_name(&dev) == name {
                    tracing::info!("Found requested output device: {}", name);
                    return Ok(dev);
                }
            }
        }
        tracing::warn!(
            "Requested output device {:?} not found, falling back to default",
            name
        );
    }
    host.default_output_device()
        .ok_or_else(|| "No output device available".into())
}

/// Start capturing audio from an input device.
/// If `device_name` is provided, attempts to find a matching device by name,
/// falling back to the default input device if not found.
/// Returns a receiver that yields PCM frames at 48 kHz mono.
pub fn start_capture(
    device_name: Option<&str>,
    frame_size: usize,
) -> Result<(cpal::Stream, mpsc::UnboundedReceiver<AudioSamples>), Box<dyn std::error::Error>> {
    let host = cpal::default_host();
    let device = find_input_device(&host, device_name)?;

    let dev_name = device_display_name(&device);
    tracing::info!("Audio capture device: {}", dev_name);

    let neg = negotiate_config(device.supported_input_configs()?)?;
    tracing::info!(
        "Capture config: {}Hz {}ch (resample={})",
        neg.device_rate,
        neg.device_channels,
        neg.needs_resample
    );

    let (tx, rx) = mpsc::unbounded_channel();

    let needs_resample = neg.needs_resample;
    let dev_channels = neg.device_channels;
    let dev_rate = neg.device_rate;

    // Shared state for the capture callback
    let resampler: Arc<Mutex<Option<LinearResampler>>> = if needs_resample {
        Arc::new(Mutex::new(Some(LinearResampler::new(dev_rate, TARGET_RATE))))
    } else {
        Arc::new(Mutex::new(None))
    };
    let buffer: Arc<Mutex<Vec<i16>>> = Arc::new(Mutex::new(Vec::with_capacity(frame_size)));
    let buffer_clone = buffer.clone();
    let resampler_clone = resampler.clone();

    let stream = device.build_input_stream(
        &neg.stream,
        move |data: &[f32], _: &cpal::InputCallbackInfo| {
            // Convert to mono i16
            let mono = if dev_channels == 1 {
                data.iter()
                    .map(|&s| (s * 32767.0).clamp(-32767.0, 32767.0) as i16)
                    .collect::<Vec<i16>>()
            } else {
                downmix_to_mono_i16(data, dev_channels)
            };

            // Resample if needed
            let samples = if let Ok(mut guard) = resampler_clone.lock() {
                if let Some(ref mut rs) = *guard {
                    rs.process(&mono)
                } else {
                    mono
                }
            } else {
                mono
            };

            // Buffer into frame_size chunks
            let mut buf = buffer_clone.lock().unwrap_or_else(|p| p.into_inner());
            buf.extend_from_slice(&samples);
            while buf.len() >= frame_size {
                let frame = buf.drain(..frame_size).collect();
                let _ = tx.send(frame);
            }
        },
        |err| {
            tracing::error!("Audio capture error: {}", err);
        },
        None,
    )?;

    stream.play()?;
    Ok((stream, rx))
}

/// Start playback on an output device.
/// If `device_name` is provided, attempts to find a matching device by name,
/// falling back to the default output device if not found.
/// Accepts PCM frames at 48 kHz mono and handles resampling/up-mixing.
pub fn start_playback(
    device_name: Option<&str>,
) -> Result<(cpal::Stream, mpsc::UnboundedSender<AudioSamples>), Box<dyn std::error::Error>> {
    let host = cpal::default_host();
    let device = find_output_device(&host, device_name)?;

    let dev_name = device_display_name(&device);
    tracing::info!("Audio playback device: {}", dev_name);

    let neg = negotiate_config(device.supported_output_configs()?)?;
    tracing::info!(
        "Playback config: {}Hz {}ch (resample={})",
        neg.device_rate,
        neg.device_channels,
        neg.needs_resample
    );

    let needs_resample = neg.needs_resample;
    let dev_channels = neg.device_channels;
    let dev_rate = neg.device_rate;

    let (tx, rx) = mpsc::unbounded_channel::<AudioSamples>();
    let rx = Arc::new(Mutex::new(rx));

    // Playback buffer stores f32 samples ready for the device
    let playback_buffer: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));

    let pb_clone = playback_buffer.clone();
    let rx_clone = rx.clone();
    let resampler: Arc<Mutex<Option<PlaybackResampler>>> = if needs_resample {
        Arc::new(Mutex::new(Some(PlaybackResampler::new(dev_rate))))
    } else {
        Arc::new(Mutex::new(None))
    };
    let resampler_clone = resampler.clone();

    // Max buffer in device samples (2 seconds)
    let max_buf = (dev_rate as usize) * (dev_channels as usize) * 2;

    let stream = device.build_output_stream(
        &neg.stream,
        move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
            let mut buf = pb_clone.lock().unwrap_or_else(|p| p.into_inner());
            // Drain any waiting frames into the buffer
            if let Ok(mut rx) = rx_clone.try_lock() {
                while let Ok(frame) = rx.try_recv() {
                    // frame is 48 kHz mono i16 — resample then up-mix
                    let resampled = if let Ok(mut guard) = resampler_clone.lock() {
                        if let Some(ref mut rs) = *guard {
                            rs.process(&frame)
                        } else {
                            frame
                        }
                    } else {
                        frame
                    };

                    if dev_channels == 1 {
                        for &s in &resampled {
                            buf.push_back(s as f32 / 32767.0);
                        }
                    } else {
                        let floats = upmix_from_mono_f32(&resampled, dev_channels);
                        buf.extend(floats.into_iter());
                    }
                }
            }
            // Cap the buffer to prevent unbounded growth
            if buf.len() > max_buf {
                let excess = buf.len() - max_buf;
                buf.drain(..excess);
                tracing::warn!("Playback buffer overflow, dropped {} samples", excess);
            }
            for sample in data.iter_mut() {
                if let Some(s) = buf.pop_front() {
                    *sample = s;
                } else {
                    *sample = 0.0;
                }
            }
        },
        |err| {
            tracing::error!("Audio playback error: {}", err);
        },
        None,
    )?;

    stream.play()?;
    Ok((stream, tx))
}
