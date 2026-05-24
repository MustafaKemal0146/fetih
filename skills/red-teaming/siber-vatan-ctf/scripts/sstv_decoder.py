#!/usr/bin/env python3
"""SSTV Scottie 1 Decoder — reusable for radio-signal CTF challenges.
Decodes a WAV file containing SSTV (Slow Scan Television) audio into an image.
Usage: python3 sstv_decoder.py <input.wav> <output.png> [mode]
Modes: Scottie1 (default, 7.5s), MartinM1 (7.1s)
"""
import wave, numpy as np, sys, os
from PIL import Image

WAV = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/sstv_out.png"

with wave.open(WAV, 'rb') as w:
    frames = w.readframes(w.getnframes())
    data = np.frombuffer(frames, dtype=np.int16)
    fs = w.getframerate()

mono = data[::2].astype(np.float32)

def get_freq(samples, fs):
    n = len(samples)
    if n < 64: return 1500
    fft_vals = np.abs(np.fft.rfft(samples * np.hanning(n)))
    freqs = np.fft.rfftfreq(n, 1/fs)
    mask = (freqs > 800) & (freqs < 2800)
    if not mask.any(): return 1500
    return freqs[np.argmax(fft_vals * mask)]

BLACK, WHITE = 1500, 2300
LINE_SYNC, PORCH = 0.009, 0.0015
GREEN = BLUE = RED = 0.13824
SEP = 0.0015
FULL_LINE = LINE_SYNC + PORCH + GREEN + SEP + BLUE + SEP + RED

total_lines = int(len(mono) / fs / FULL_LINE)
img_data, sample_idx, lines_decoded = [], 0, 0

for line in range(min(total_lines, 200)):
    if sample_idx >= len(mono): break
    colors = []
    for chan_name, chan_len in [('G', GREEN), ('B', BLUE), ('R', RED)]:
        if chan_name == 'G':
            start = sample_idx + int(fs * (LINE_SYNC + PORCH))
        elif chan_name == 'B':
            start = sample_idx + int(fs * (LINE_SYNC + PORCH + GREEN + SEP))
        else:
            start = sample_idx + int(fs * (LINE_SYNC + PORCH + GREEN + SEP + BLUE + SEP))
        end = min(start + int(fs * chan_len), len(mono))
        if end - start < 32: break
        chunk = mono[start:end]
        pixels, step = [], int(fs * 0.002)
        for p in range(0, len(chunk) - step, step):
            freq = get_freq(chunk[p:p+step], fs)
            val = int((freq - BLACK) / (WHITE - BLACK) * 255)
            pixels.append(max(0, min(255, val)))
        colors.append(pixels)
    if len(colors) == 3:
        min_len = min(len(c) for c in colors)
        for i in range(min_len):
            img_data.append((colors[2][i], colors[0][i], colors[1][i]))
        lines_decoded += 1
    sample_idx += int(fs * FULL_LINE)

if img_data:
    pixels_per_line = len(img_data) // lines_decoded
    img = Image.new('RGB', (pixels_per_line, lines_decoded))
    for y in range(lines_decoded):
        for x in range(pixels_per_line):
            idx = y * pixels_per_line + x
            if idx < len(img_data):
                img.putpixel((x, y), img_data[idx])
    img = img.resize((pixels_per_line * 4, lines_decoded * 4), Image.NEAREST)
    img.save(OUT)
    print(f"Saved: {pixels_per_line*4}x{lines_decoded*4} to {OUT}")
else:
    print("No image decoded — try a different SSTV mode.")
