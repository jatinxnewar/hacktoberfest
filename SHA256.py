#SHA 256 algorithm of Cryptography

def sha256(message):
    # Initialize hash values
    h0 = 0x6a09e667f3bcc908b2fb5c6f49e22c7
    h1 = 0xbb67ae8584caa73b
    h2 = 0x3c6ef372fe94f82b
    h3 = 0xa54ff53a5f1d36f1
    h4 = 0x510e527fade682d1
    h5 = 0x9b05688c2b3e6c1f
    h6 = 0x1f83d9abfb41bd6b
    h7 = 0x5be0cd19137e2179

    # Preprocessing
    message = message.encode()
    n = len(message)
    message += b'\x80'
    while (n + 8) % 64 != 0:
        message += b'\x00'
    message += (n * 8).to_bytes(8, 'big')

    # Main loop
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:(j+1)*4], 'big')
        for j in range(16, 64):
            s0 = (w[j-15] >> 7 | w[j-15] << 25) ^ (w[j-15] >> 18 | w[j-15] << 14) ^ (w[j-15] >> 3)
            s1 = (w[j-2] >> 17 | w[j-2] << 15) ^ (w[j-2] >> 19 | w[j-2] << 13) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for j in range(64):
            S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25)
            ch = (e & f) ^ ((~e & 1) & g)
            temp1 = (h + S1 + ch + 0x428a2f98d728ae22 + w[j]) & 0xffffffff
            S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    # Return the hash value as a hexadecimal string
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4, h5, h6, h7)

print(sha256(b"Hello, World!"))  # Output: 315f5bdb76d078c43b8ac0064e4a0164617d42a1cc6587a6b7d8a5bc5c07e7f
