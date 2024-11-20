import sys
import struct
import zlib
import binascii

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
    
    # Remove the "XXTEA" header if present
    if encrypted_data[:5] == b'XXTEA':
        encrypted_data = encrypted_data[5:]
        print("Removed XXTEA header")

    # Decrypt the data
    decrypted_data = decrypt(encrypted_data, key)
    
    print(f"Decrypted data size: {len(decrypted_data)} bytes")
    print(f"First 20 bytes of decrypted data: {binascii.hexlify(decrypted_data[:20])}")
    
    # Try to decompress if it's zlib compressed
    try:
        decompressed_data = zlib.decompress(decrypted_data)
        print("Successfully decompressed with zlib")
        decrypted_data = decompressed_data
    except zlib.error:
        print("Not zlib compressed or decompression failed")
    
    # Remove any padding
    decrypted_data = decrypted_data.rstrip(b'\0')

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Final output size: {len(decrypted_data)} bytes")
    print(f"First 20 bytes of final output: {binascii.hexlify(decrypted_data[:20])}")

# Usage
if len(sys.argv) != 4:
    print("Usage: python jscd_old.py <input_file> <output_file> <key>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
key = sys.argv[3]

decrypt_file(input_file, output_file, key)
print(f"Decrypted {input_file} to {output_file}")
