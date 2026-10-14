---
name: steganography-techniques
description: >-
  Steganography detection and extraction playbook. Use when analyzing images (LSB, PNG chunks, JPEG DCT, EXIF), audio (spectrogram, DTMF), files (polyglots, appended data, ADS), and text (whitespace, zero-width, homoglyphs) for hidden data.
---

# SKILL: Steganography Techniques — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert steganography detection and extraction. Covers image (LSB, PNG chunk hiding, JPEG DCT, EXIF, dimension tricks), audio (spectrogram, LSB, DTMF, morse), file (polyglots, binwalk, NTFS ADS, steghide), and text (whitespace, zero-width, homoglyphs). See [STEGO_TOOLS_GUIDE.md](./STEGO_TOOLS_GUIDE.md) for full tool reference.

---

## 1. IMAGE STEGANOGRAPHY

### LSB
```bash
zsteg image.png                       # auto-detect all LSB patterns
zsteg image.png -a                    # try all methods
zsteg image.png -E "b1,rgb,lsb,xy"   # specific extraction
stegoveritas image.png                # comprehensive automated analysis
```

### PNG
```bash
pngcheck -v image.png                 # validate structure, find hidden chunks
# Hidden chunks: tEXt, zTXt, iTXt may contain data

# CRC vs dimensions trick (image was cropped)
python3 -c "
import struct, zlib
with open('image.png','rb') as f:
    data = f.read()
ihdr = data[12:29]
for h in range(1,2000):
    for w in range(1,2000):
        new_ihdr = struct.pack('>II',w,h) + ihdr[8:]
        if zlib.crc32(b'IHDR'+new_ihdr) & 0xffffffff == struct.unpack('>I',data[29:33])[0]:
            print(f'Width: {w}, Height: {h}')
"
```

### JPEG
```bash
steghide extract -sf image.jpg                # extract (no passphrase)
steghide extract -sf image.jpg -p PASSWORD    # with passphrase
stegseek image.jpg /usr/share/wordlists/rockyou.txt  # brute force (10000x faster)
jsteg reveal image.jpg output.txt             # JPEG LSB
exiftool -b -ThumbnailImage image.jpg > thumb.jpg  # extract thumbnail
```

### EXIF Metadata
```bash
exiftool image.jpg
exiftool -Comment image.jpg
strings image.jpg | grep -i "flag\|key\|secret"
```

---

## 2. AUDIO STEGANOGRAPHY

```bash
# Spectrogram
sox audio.wav -n spectrogram -o spectro.png
# Sonic Visualiser: Layer -> Add Spectrogram

# Audio LSB
python3 WavSteg.py -r -i audio.wav -o output.txt -n 1

# DTMF tones
multimon-ng -t wav -a DTMF audio.wav

# SSTV (image in audio)
qsstv

# Check for appended data
python3 -c "
import wave, os
w = wave.open('audio.wav','rb')
expected = w.getnframes() * w.getnchannels() * w.getsampwidth() + 44
actual = os.path.getsize('audio.wav')
if actual > expected:
    print(f'Extra data: {actual - expected} bytes')
"
```

---

## 3. FILE STEGANOGRAPHY

```bash
# Binwalk - scan and extract embedded files
binwalk suspicious_file
binwalk -e image.png
binwalk --dd='.*' image.png

# Try polyglot (PDF+ZIP, JPEG+ZIP, JPEG+RAR, PNG+ZIP)
unzip image.jpg -d extracted/
7z x image.jpg -oextracted/

# File carving
foremost -i suspicious_file -o output_dir/

# Manual extraction from offset
dd if=suspicious_file bs=1 skip=$((0x1234)) of=extracted.zip

# NTFS ADS (Windows)
dir /r file.txt
Get-Content file.txt -Stream hidden_stream
```

---

## 4. TEXT STEGANOGRAPHY

```bash
# Whitespace (tab/space encoding)
stegsnow -C message.txt
stegsnow -C -p PASSWORD message.txt
cat -A file.txt | head  # show tabs (^I)

# Zero-width characters
python3 -c "
text = open('message.txt','r').read()
hidden = [c for c in text if ord(c) in [0x200b, 0x200c, 0x200d, 0xfeff]]
print(f'Found {len(hidden)} zero-width chars')
binary = ''.join('0' if ord(c)==0x200b else '1' for c in hidden)
"

# Homoglyphs
python3 -c "
text = open('message.txt','r').read()
for i, c in enumerate(text):
    if ord(c) > 127:
        import unicodedata
        print(f'Position {i}: {c!r} = U+{ord(c):04X} ({unicodedata.name(c,"?")})')
"
```

---

## 5. DECISION TREE

```
Suspect hidden data — file type?
├── PNG/BMP: exiftool → pngcheck → zsteg → CRC/dimensions brute → binwalk -e → polyglot
├── JPEG: exiftool → steghide → stegseek brute → jsteg → binwalk -e → thumbnail
├── GIF: extract all frames → gifsicle palette → binwalk -e
├── Audio: spectrogram → WavSteg LSB → DTMF → morse → SSTV → size check
├── Text: stegsnow whitespace → zero-width Unicode → homoglyphs → multiple base decodings
└── Any: strings -n 8 | grep flag; binwalk -e; file; xxd header; NTFS ADS
```
