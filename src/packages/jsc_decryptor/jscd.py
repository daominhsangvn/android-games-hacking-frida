import sys
import struct
import gzip
import binascii
import io

def _long2str(v, w):
    n = (len(v) - 1) << 2
    if w:
        m = v[-1]
        if (m < n - 3) or (m > n): return b''
        n = m
    s = struct.pack('<%iL' % len(v), *v)
    return s[0:n] if w else s

def _str2long(s, w):
    n = len(s)
    m = (4 - (n & 3) & 3) + n
    s = s.ljust(m, b"\0")
    v = list(struct.unpack('<%iL' % (m >> 2), s))
    if w: v.append(n)
    return v

def decrypt(data, key):
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')
    if data == b"": return data
    v = _str2long(data, False)
    k = _str2long(key.ljust(16, b"\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    sum = (q * 0x9E3779B9) & 0xFFFFFFFF
    while (sum != 0):
        e = sum >> 2 & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xFFFFFFFF
            y = v[p]
        z = v[n]
        v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xFFFFFFFF
        y = v[0]
        sum = (sum - 0x9E3779B9) & 0xFFFFFFFF
    return _long2str(v, True)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    print(f"Original file size: {len(encrypted_data)} bytes")
    print(f"First 20 bytes: {binascii.hexlify(encrypted_data[:20])}")

    # Decrypt the data
    decrypted_data = decrypt(encrypted_data, key)

    print(f"Decrypted data size: {len(decrypted_data)} bytes")
    print(f"First 20 bytes of decrypted data: {binascii.hexlify(decrypted_data[:20])}")

    # Try to decompress if it's gzip compressed
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(decrypted_data)) as gz:
            decompressed_data = gz.read()
        print("Successfully decompressed with gzip")
        decrypted_data = decompressed_data
    except Exception as e:
        print(f"Gzip decompression failed: {str(e)}")

    # Remove any padding
    decrypted_data = decrypted_data.rstrip(b'\0')

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"Final output size: {len(decrypted_data)} bytes")
    print(f"First 100 bytes of final output: {decrypted_data[:100].decode('utf-8', errors='ignore')}")

def encrypt(data, key):
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')
    if data == b"": return data
    v = _str2long(data, True)
    k = _str2long(key.ljust(16, b"\0"), False)
    n = len(v) - 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    sum = 0
    while (q > 0):
        sum = (sum + 0x9E3779B9) & 0xFFFFFFFF
        e = sum >> 2 & 3
        for p in range(0, n):
            y = v[p + 1]
            v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xFFFFFFFF
        z = v[n]
        q -= 1
    return _long2str(v, False)

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    print(f"Original file size: {len(data)} bytes")
    
    # Optionally compress with gzip before encryption
    try:
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode='wb') as gz:
            gz.write(data)
        data = compressed_data.getvalue()
        print("Successfully compressed with gzip")
    except Exception as e:
        print(f"Gzip compression failed: {str(e)}")

    # Encrypt the data
    encrypted_data = encrypt(data, key)
    
    print(f"Encrypted data size: {len(encrypted_data)} bytes")
    print(f"First 20 bytes of encrypted data: {binascii.hexlify(encrypted_data[:20])}")

    # Write the encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    print(f"Encrypted {input_file} to {output_file}")

# Usage
if len(sys.argv) not in [4, 5]:
    print("Usage:")
    print("  Decrypt: python jscd.py decrypt <input_file> <output_file> <key>")
    print("  Encrypt: python jscd.py encrypt <input_file> <output_file> <key>")
    sys.exit(1)

mode = sys.argv[1] if len(sys.argv) == 5 else "decrypt"
input_file = sys.argv[-3]
output_file = sys.argv[-2]
key = sys.argv[-1]

if mode == "decrypt":
    decrypt_file(input_file, output_file, key)
    print(f"Decrypted {input_file} to {output_file}")
elif mode == "encrypt":
    encrypt_file(input_file, output_file, key)
    print(f"Encrypted {input_file} to {output_file}")
else:
    print("Invalid mode. Use 'encrypt' or 'decrypt'")
    sys.exit(1)
