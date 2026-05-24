# SSTV Signal Analysis — "Yankı" Challenge

**Challenge**: 7.5-second WAV (yanki.wav) of a suspicious radio transmission.

## File Analysis
- Format: RIFF WAVE, Microsoft PCM, 16-bit, stereo 44100 Hz
- Size: 1.3MB (1,323,044 bytes)
- Duration: 7.5 seconds (330,750 frames per channel)
- Channels: 2 (stereo — take left channel for mono)

## Detection Method
1. WAV analysis: `ffprobe` shows format, `scipy.signal.spectrogram` shows frequency over time
2. FFT across 20ms windows reveals frequencies in the 800-2800 Hz range
3. Frequencies change every ~138ms — consistent with SSTV color bar scanning
4. 7.5s = Scottie 1 format (7.1s = Martin M1)

## Scottie 1 SSTV Frame Structure
Each scan line:
- 9ms sync pulse @ 1200 Hz
- 1.5ms channel sync @ 1200 Hz
- 1.5ms porch @ 1500 Hz
- 138.24ms Green channel (1500-2300 Hz = black-white gradient)
- 138.24ms Blue channel
- 138.24ms Red channel

~14-18 lines total in 7.5 seconds.

## Available Decoders
| Tool | Type | Works Headless? |
|------|------|----------------|
| `qsstv` | Linux GUI | No (X11 required) |
| `fldigi` | Linux GUI | No (X11 required) |
| `pysstv` (Python) | Encoder only | N/A |
| `rx-sstv` (PyPI) | Not available | N/A |
| Custom Python | From scratch | Yes, but complex |

## Practical Python Decoder (Custom Implementation)\n\nSince no headless SSTV decoder is available via pip, implement Scottie 1 manually:\n\n**Key parameters:**\n- Sync: 1200 Hz (9ms)\n- Porch: 1500 Hz (1.5ms)\n- Black/White range: 1500-2300 Hz\n- Channel length: 138.24ms per color (G, B, R)\n- Step size: 2ms per pixel\n- Total pixels per line: ~69 (138.24ms / 2ms)\n- Total lines: ~17-18\n\n**Algorithm:**\n1. Load WAV as mono int16 array\n2. For each line (~0.427s):\n   - Skip sync + porch\n   - For each color channel (G, B, R): read 138.24ms chunk\n   - Within each chunk, step every 2ms: compute FFT, find dominant frequency in 800-2800 Hz band\n   - Map frequency: `int((freq - 1500) / (2300 - 1500) * 255)` → clamp to 0-255\n3. Stack rows as RGB image (R, G, B channel order)\n4. Resize output 10x for readability\n\n**Limitations:**\n- Low resolution (~69x17 pixels)\n- Frequency resolution poor with only 88 samples (2ms at 44100Hz)\n- Output may need AI upscaling or human interpretation\n- Better to run within an actual GUI decoder (qsstv) if available\n\n## Fallback\n1. Upload to online SSTV decoder service\n2. Try `xvfb-run qsstv yanki.wav` to run GUI in virtual framebuffer\n3. Use AI Studio / Gemini to analyze the decoded low-res image
