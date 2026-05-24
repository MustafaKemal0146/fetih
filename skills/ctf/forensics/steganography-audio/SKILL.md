---
name: steganography-audio
description: "Ses steganografi — WAV LSB, DTMF decode, spektogram analizi, DeepSound, Morse code ve Python ile tam çözüm şablonları."
tags: [ctf, forensics, stego, audio, wav, mp3, lsb, dtmf, spectrogram, deepsound, morse, sonic-visualiser, audacity, sox, goertzel]
triggers:
  - "WAV dosyası"
  - "MP3 dosyası"
  - "ses dosyasında gizli veri"
  - "DTMF"
  - "spektogram"
  - "audio stego"
  - "DeepSound"
  - "Sonic Visualiser"
  - "Audacity"
  - "ses analizi"
  - "frekans analizi"
  - "morse code audio"
  - "audio forensics"
difficulty: medium
category: forensics
solved_challenges:
  - "CatTheQuest CTF 2024 - Deep Sound Deep Vision (spektogram + DeepSound password → MONSTERS.txt → decimal ASCII → flag)"
  - "çeşitli CTF DTMF decode (telefon tuşları → rakam dizisi → flag)"
  - "ångstromCTF DTMF challenge"
---

# Ses Steganografi Analizi

## Ne Zaman Kullan

Aşağıdaki işaretlerden herhangi birini görürsen bu skill'i tetikle:

- `.wav`, `.mp3`, `.flac`, `.ogg`, `.aiff` dosyası verilmiş
- Ses garip tınlıyor, arka planda tuş sesi/bip/ton var (DTMF/Morse şüphesi)
- Challenge'da "hidden in audio", "secret frequency", "listen carefully" geçiyor
- Spektogram incelenmesini öneren ipucu var
- DeepSound, MP3Stego adı geçiyor

---

## Araç Seti

```bash
# Sonic Visualiser — spektogram görselleştirme (GUI, en önemli araç)
sudo apt install sonic-visualiser

# Audacity — ses düzenleme ve görselleştirme
sudo apt install audacity

# DeepSound — Windows GUI, LSB gizleme/çıkarma
# İndir: http://jpinsoft.net/deepsound/download.aspx

# sox — CLI ses dönüştürme
sudo apt install sox

# Python kütüphaneleri
pip install scipy numpy wave pydub

# ffmpeg — format dönüştürme
sudo apt install ffmpeg

# stegolsb — ses LSB CLI
pip install stegolsb
```

---

## Spektogram Analizi — Sonic Visualiser

Spektogram, ses dosyasındaki frekansların zamana göre görsel temsilidir. Gizli mesajlar görsel olarak frekans katmanına kodlanabilir (görüntü gibi görünür).

### Sonic Visualiser Adımları

```
1. Sonic Visualiser'ı aç
2. Dosya → Aç → challenge.wav
3. Layer menüsü → Add Spectrogram
4. Properties panelinde:
   - Window: 2048 ya da 4096 (daha yüksek = daha iyi frekans çözünürlüğü)
   - Colourmap: Sunset ya da Inferno (kontrastı artırır)
   - Scale: dBV²
5. Spektogramı yatay kaydır, gizli metin/görüntü ara
6. Çok yüksek frekanslara bak (>10kHz — insan kulağı duymaz, CTF favorisi)
```

### Python ile Spektogram Göster

```python
#!/usr/bin/env python3
"""
WAV dosyasının spektogramını görselleştir.
Çalıştır: python3 spectrogram.py challenge.wav
"""
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
import sys

wav_file = sys.argv[1] if len(sys.argv) > 1 else "challenge.wav"

sample_rate, data = wavfile.read(wav_file)

# Stereo → mono
if data.ndim > 1:
    data = data[:, 0]

print(f"[*] Sample rate: {sample_rate} Hz")
print(f"[*] Duration: {len(data)/sample_rate:.2f} saniye")
print(f"[*] Samples: {len(data)}")

# Spektogram çiz
plt.figure(figsize=(20, 8))
plt.specgram(data, Fs=sample_rate, NFFT=4096, noverlap=2048,
             cmap='inferno', vmin=-100, vmax=0)
plt.colorbar(label='Güç (dBFS)')
plt.xlabel('Zaman (s)')
plt.ylabel('Frekans (Hz)')
plt.title(f'Spektogram: {wav_file}')
plt.ylim(0, sample_rate // 2)  # Nyquist'e kadar
plt.savefig('spectrogram.png', dpi=150, bbox_inches='tight')
plt.show()
print("[+] Spektogram kaydedildi: spectrogram.png")
```

---

## Gerçek Örnek: CatTheQuest CTF 2024 — Deep Sound Deep Vision

### Senaryo
`challenge.wav` verilmiş. Dinleyince sıradan ses. Ancak spektogramda görünür metin var.

### Çözüm Adımları

```
Adım 1: Sonic Visualiser ile spektogramı aç
         → Yüksek frekanslarda "THE_MONSTER_IS_YOU" yazısı görünüyor
         → Bu DeepSound şifresi!

Adım 2: DeepSound ile ses dosyasını analiz et
         → DeepSound aç → challenge.wav'ı yükle
         → Şifreli içerik gösteriyor
         → Password: "THE_MONSTER_IS_YOU"
         → Extract → MONSTERS.txt çıkarıldı

Adım 3: MONSTERS.txt içeriğini oku
         → Onluk (decimal) sayı dizisi: "67 84 70 123 77 ..."

Adım 4: Decimal ASCII'den flag'e çevir
```

```python
#!/usr/bin/env python3
"""CatTheQuest decimal ASCII → flag dönüştürücü."""

# MONSTERS.txt içeriği (decimal sayılar)
decimal_str = "67 84 70 123 77 79 78 83 84 69 82 95 70 76 65 71 125"
# Örnek — gerçek CTF'den sayıları buraya yapıştır

numbers = list(map(int, decimal_str.split()))
flag = ''.join(chr(n) for n in numbers)
print(f"[+] Flag: {flag}")
# Çıktı: CTF{MONSTER_FLAG}
```

### Alternatif: DeepSound olmadan CLI

```bash
# MP3Stego kontrolü
mp3stego-decode -X challenge.mp3 output.txt

# stegolsb ile
wavsteg -r -i challenge.wav -o output.txt -n 1

# sox ile kanalları ayır (stereo'dan bir kanal gizli olabilir)
sox challenge.wav left.wav remix 1   # sol kanal
sox challenge.wav right.wav remix 2  # sağ kanal

# Fark kanalı (sağ - sol, stereo içinde gizlenmiş sinyal)
sox -M left.wav right.wav merged.wav
sox merged.wav diff.wav remix 1v1,2v-1  # fark
```

---

## DTMF Decode

DTMF (Dual-Tone Multi-Frequency): Telefon tuş seslerinin frekans çiftiyle kodlanması.
CTF'lerde ses dosyası DTMF tonları içeriyorsa, rakam/karakter dizisi → dönüştürme → flag.

### DTMF Frekans Tablosu

```
        1209 Hz  1336 Hz  1477 Hz  1633 Hz
697 Hz    1        2        3        A
770 Hz    4        5        6        B
852 Hz    7        8        9        C
941 Hz    *        0        #        D
```

### Python Goertzel Algoritması ile DTMF Decode

```python
#!/usr/bin/env python3
"""
WAV dosyasındaki DTMF tonlarını decode et.
Çalıştır: python3 dtmf_decode.py tones.wav
"""
import numpy as np
from scipy.io import wavfile
import sys

def goertzel(samples: np.ndarray, sample_rate: int, target_freq: float) -> float:
    """Goertzel algoritması — belirli bir frekansın gücünü hesaplar."""
    N = len(samples)
    k = int(0.5 + N * target_freq / sample_rate)
    omega = 2 * np.pi * k / N
    coeff = 2 * np.cos(omega)
    
    s_prev2 = 0.0
    s_prev1 = 0.0
    
    for sample in samples:
        s = sample + coeff * s_prev1 - s_prev2
        s_prev2 = s_prev1
        s_prev1 = s
    
    power = s_prev2**2 + s_prev1**2 - coeff * s_prev1 * s_prev2
    return power

# DTMF frekans matrisi
DTMF_FREQS = {
    'row': [697, 770, 852, 941],
    'col': [1209, 1336, 1477, 1633]
}

DTMF_KEYS = [
    ['1', '2', '3', 'A'],
    ['4', '5', '6', 'B'],
    ['7', '8', '9', 'C'],
    ['*', '0', '#', 'D'],
]

def decode_dtmf_frame(frame: np.ndarray, sample_rate: int) -> str:
    """Bir ses çerçevesini DTMF karakterine decode et."""
    # Normalize et
    frame = frame.astype(np.float64)
    
    row_powers = [goertzel(frame, sample_rate, f) for f in DTMF_FREQS['row']]
    col_powers = [goertzel(frame, sample_rate, f) for f in DTMF_FREQS['col']]
    
    row_idx = np.argmax(row_powers)
    col_idx = np.argmax(col_powers)
    
    # Güç eşiği — gürültüyü filtrele
    THRESHOLD = 1e6
    if row_powers[row_idx] < THRESHOLD or col_powers[col_idx] < THRESHOLD:
        return None
    
    return DTMF_KEYS[row_idx][col_idx]

def decode_wav(wav_file: str) -> str:
    sample_rate, data = wavfile.read(wav_file)
    
    # Stereo → mono
    if data.ndim > 1:
        data = data[:, 0]
    
    data = data.astype(np.float64)
    
    # Çerçeve boyutu: ~50ms
    frame_size = int(sample_rate * 0.05)
    
    digits = []
    prev_digit = None
    
    i = 0
    while i + frame_size <= len(data):
        frame = data[i:i + frame_size]
        digit = decode_dtmf_frame(frame, sample_rate)
        
        if digit and digit != prev_digit:
            digits.append(digit)
        
        prev_digit = digit
        i += frame_size // 2  # %50 overlap
    
    return ''.join(digits)

if __name__ == "__main__":
    wav_file = sys.argv[1] if len(sys.argv) > 1 else "dtmf.wav"
    
    print(f"[*] DTMF decode: {wav_file}")
    result = decode_wav(wav_file)
    print(f"[+] Bulunan rakamlar: {result}")
    
    # T9 klavye → harf dönüşümü (gerekirse)
    # 2=ABC, 3=DEF, 4=GHI, 5=JKL, 6=MNO, 7=PQRS, 8=TUV, 9=WXYZ
    t9_map = {
        '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
        '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ'
    }
    print(f"\n[*] T9 karşılıkları (sırayla): ", end="")
    for d in result:
        if d in t9_map:
            print(f"{d}={t9_map[d]}", end=" ")
    print()
    
    # Decimal ASCII dene
    if all(c.isdigit() for c in result) and len(result) % 2 == 0:
        try:
            pairs = [int(result[i:i+2]) for i in range(0, len(result), 2)]
            text = ''.join(chr(p) for p in pairs if 32 <= p < 127)
            print(f"[+] 2 haneli decimal ASCII: {text}")
        except Exception:
            pass
```

---

## WAV LSB Python ile Çıkarma

```python
#!/usr/bin/env python3
"""WAV LSB steganografi — en düşük bit düzleminden veri çıkar."""
import wave
import sys

def extract_lsb_wav(wav_file: str, n_bits: int = 1, out_file: str = "lsb_output.bin"):
    """
    wav_file : WAV dosyası
    n_bits   : kaç bit çıkarılacak (1 = LSB, 2 = iki bit, vb.)
    """
    with wave.open(wav_file, 'rb') as w:
        n_frames   = w.getnframes()
        n_channels = w.getnchannels()
        sampwidth  = w.getsampwidth()  # byte cinsinden örnek genişliği
        frames     = w.readframes(n_frames)
    
    print(f"[*] {wav_file}: {n_frames} frame, {n_channels} kanal, {sampwidth*8}-bit")
    
    samples = list(frames)
    bits = []
    
    mask = (1 << n_bits) - 1  # örn. n_bits=1 → 0b00000001
    
    for sample in samples:
        for bit_pos in range(n_bits - 1, -1, -1):
            bits.append((sample >> bit_pos) & 1)
    
    # Bit dizisini byte'lara çevir
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        result.append(byte)
        
        # Null-terminated string bitişi
        if result[-1] == 0 and len(result) > 10:
            text_so_far = result[:-1].decode('utf-8', errors='ignore')
            if any(p in text_so_far for p in ['flag{', 'CTF{', 'HTB{']):
                print(f"[!] Flag bulundu: {text_so_far}")
                break
    
    with open(out_file, "wb") as f:
        f.write(result)
    
    print(f"[+] {len(result)} byte çıkarıldı: {out_file}")
    print(f"[+] İlk 50 byte ASCII: {result[:50].decode('latin-1', errors='replace')}")
    
    return bytes(result)

if __name__ == "__main__":
    wav = sys.argv[1] if len(sys.argv) > 1 else "audio.wav"
    extract_lsb_wav(wav, n_bits=1)          # LSB
    # extract_lsb_wav(wav, n_bits=2)        # 2 LSB
    # stegolsb alternatif: wavsteg -r -i audio.wav -o out.txt -n 1
```

---

## Morse Code Audio Decode

```python
#!/usr/bin/env python3
"""WAV dosyasından Morse kodu decode et."""
import numpy as np
from scipy.io import wavfile

def decode_morse_audio(wav_file: str):
    sample_rate, data = wavfile.read(wav_file)
    
    if data.ndim > 1:
        data = data[:, 0]
    
    # Enerji zarfını hesapla (mutlak değer + yumuşatma)
    envelope = np.abs(data.astype(np.float64))
    window = int(sample_rate * 0.01)  # 10ms pencere
    envelope = np.convolve(envelope, np.ones(window)/window, mode='same')
    
    # Eşik: ortalamanın 2 katı
    threshold = np.mean(envelope) * 2
    
    # Açık/kapalı segmentleri bul
    signal_on = envelope > threshold
    
    # Segment uzunluklarını hesapla
    segments = []
    current_state = signal_on[0]
    count = 0
    
    for s in signal_on:
        if s == current_state:
            count += 1
        else:
            segments.append((current_state, count / sample_rate * 1000))  # ms
            current_state = s
            count = 1
    segments.append((current_state, count / sample_rate * 1000))
    
    # Kısa/uzun ton sürelerini bul
    on_durations = [d for state, d in segments if state and d > 10]
    if not on_durations:
        print("[-] Sinyal tespit edilemedi")
        return
    
    median_dur = np.median(on_durations)
    dot_threshold = median_dur * 2  # kısa ton
    
    # Morse sembollerine çevir
    MORSE_CODE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9',
    }
    
    morse_str = ""
    for state, duration in segments:
        if state:  # ton açık
            morse_str += '.' if duration < dot_threshold else '-'
        else:  # sessizlik
            if duration > dot_threshold * 6:  # kelime arası
                morse_str += ' / '
            elif duration > dot_threshold * 2:  # harf arası
                morse_str += ' '
    
    print(f"[*] Morse: {morse_str}")
    
    # Decode et
    words = morse_str.split(' / ')
    decoded = []
    for word in words:
        letters = word.split()
        decoded_word = ''.join(MORSE_CODE.get(l, '?') for l in letters)
        decoded.append(decoded_word)
    
    result = ' '.join(decoded)
    print(f"[+] Decoded: {result}")
    return result

if __name__ == "__main__":
    import sys
    wav = sys.argv[1] if len(sys.argv) > 1 else "morse.wav"
    decode_morse_audio(wav)
```

---

## Tuzaklar

- **Sample rate farkı**: 8000 Hz (telefon kalitesi) ile 44100 Hz (CD kalitesi) fark büyük. DTMF frekansları her sample rate için yeniden hesaplanmalı — Goertzel algoritması bunu otomatik yapar.
- **Stereo vs mono**: Gizli veri sadece sol ya da sadece sağ kanalda olabilir. Her kanalı ayrı ayrı analiz et: `sox audio.wav -c 1 left.wav remix 1`
- **MP3 kayıplı sıkıştırma**: MP3, LSB bilgisini yok eder. WAV'a çevirip LSB çıkarmaya çalışma — anlamsız sonuç alırsın. MP3 için MP3Stego ya da spektogram ara.
- **DeepSound şifresi**: CTF'de DeepSound şifresi çoğunlukla spektogramdan okunur. Sonic Visualiser'da çok yüksek frekanslara (>15kHz) özellikle bak.
- **DTMF çakışması**: Arka plan gürültüsü false positive yaratabilir. Goertzel eşiğini (THRESHOLD) yükselt ya da sadece belirgin ton geçişlerini say.
- **Morse hız değişkeni**: WPM (words per minute) farklı olursa median hesabı bozulur. Kısa/uzun oranı sabit kalır (1:3) ama mutlak süre değişir.
- **WAV bit derinliği**: 8-bit WAV örnekler işaretsiz (0-255), 16-bit işaretli (-32768 ile 32767). `wave` modülü raw byte döner — bit derinliğine göre yorumla.
- **Boş/sessiz bölgeler**: Dosyanın sonunda uzun sessizlik varsa binwalk ile kontrol et — başka bir dosya eklenmiş olabilir.
