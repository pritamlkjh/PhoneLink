package com.phonelink.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Pure-Kotlin constant-time Curve25519 primitives (RFC 7748 X25519 & RFC 8032 Ed25519 verify).
 * Guarantees identical cryptographic behavior across Android API 26..35 and host JVMs
 * without relying on JCA X25519/Ed25519 provider availability.
 */
object Curve25519Primitives {

    private val D = longArrayOf(
        0x78a3L, 0x1359L, 0x4dcaL, 0x75ebL, 0xd8abL, 0x4141L, 0x0a4dL, 0x0070L,
        0xe898L, 0x7779L, 0x4079L, 0x8cc7L, 0xfe73L, 0x2b6fL, 0x6ceeL, 0x5203L
    )
    private val D2 = longArrayOf(
        0xf159L, 0x26b2L, 0x9b94L, 0xebd6L, 0xb156L, 0x8283L, 0x149aL, 0x00e0L,
        0xd130L, 0xeef3L, 0x80f2L, 0x198eL, 0xfce7L, 0x56dfL, 0xd9dcL, 0x2406L
    )
    private val X = longArrayOf(
        0xd51aL, 0x8f25L, 0x2d60L, 0xc956L, 0xa7b2L, 0x9525L, 0xc760L, 0x692cL,
        0xdc5cL, 0xfdd6L, 0xe231L, 0xc0a4L, 0x53feL, 0xcd6eL, 0x36d3L, 0x2169L
    )
    private val Y = longArrayOf(
        0x6658L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L,
        0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L, 0x6666L
    )
    private val I = longArrayOf(
        0xa0b0L, 0x4a0eL, 0x1b27L, 0xc4eeL, 0xe478L, 0xad2fL, 0x1806L, 0x2f43L,
        0xd7a7L, 0x3dfbL, 0x0099L, 0x2b4dL, 0xdf0bL, 0x4fc1L, 0x2480L, 0x2b83L
    )
    private val _121665 = longArrayOf(
        0xdb41L, 1L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L
    )
    private val GF0 = LongArray(16)
    private val GF1 = LongArray(16).apply { this[0] = 1L }

    // Curve25519 subgroup order L (little-endian 64 bytes for TweetNaCl modL, 32 bytes for S < L check)
    private val L = longArrayOf(
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    )

    private val BASE_9 = ByteArray(32).apply { this[0] = 9 }

    fun x25519GeneratePrivateKey(random: SecureRandom = SecureRandom()): ByteArray {
        val priv = ByteArray(32)
        random.nextBytes(priv)
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        return priv
    }

    fun x25519PublicFromPrivate(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
        return x25519ScalarMult(privateKey, BASE_9)
    }

    fun x25519ComputeSharedSecret(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
        require(peerPublicKey.size == 32) { "X25519 public key must be 32 bytes" }
        val shared = x25519ScalarMult(privateKey, peerPublicKey)
        var nonZero = 0
        for (b in shared) {
            nonZero = nonZero or (b.toInt() and 0xff)
        }
        if (nonZero == 0) {
            throw SecurityException("Rejected low-order X25519 public key (all-zero shared secret)")
        }
        return shared
    }

    fun x25519ScalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        val z = scalar.copyOf(32)
        z[0] = (z[0].toInt() and 248).toByte()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()

        val pMasked = point.copyOf(32)
        // RFC 7748 Section 5 decodeUCoordinate clears bit 255
        pMasked[31] = (pMasked[31].toInt() and 0x7f).toByte()

        val x = LongArray(80)
        val a = LongArray(16)
        val b = LongArray(16)
        val c = LongArray(16)
        val d = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)

        unpack25519(x, pMasked)
        for (i in 0 until 16) {
            b[i] = x[i]
            d[i] = 0L
            a[i] = 0L
            c[i] = 0L
        }
        a[0] = 1L
        d[0] = 1L

        for (i in 254 downTo 0) {
            val r = ((z[i ushr 3].toInt() ushr (i and 7)) and 1)
            sel25519(a, b, r)
            sel25519(c, d, r)
            A(e, a, c)
            Z(a, a, c)
            A(c, b, d)
            Z(b, b, d)
            S(d, e)
            S(f, a)
            M(a, c, a)
            M(c, b, e)
            A(e, a, c)
            Z(a, a, c)
            S(b, a)
            Z(c, d, f)
            M(a, c, _121665)
            A(a, a, d)
            M(c, c, a)
            M(a, d, f)
            M(d, b, x)
            S(b, e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }
        for (i in 0 until 16) {
            x[i + 16] = a[i]
            x[i + 32] = c[i]
            x[i + 48] = b[i]
            x[i + 64] = d[i]
        }
        val invC = LongArray(16)
        inv25519(invC, x.copyOfRange(32, 48))
        M(a, x.copyOfRange(16, 32), invC)
        val out = ByteArray(32)
        pack25519(out, a)
        return out
    }

    /**
     * Verifies an RFC 8032 Ed25519 signature (`64 bytes`) over `message` using `publicKey` (`32 bytes`).
     */
    fun ed25519Verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != 64 || publicKey.size != 32) return false
        if (!isCanonicalScalar(signature, 32)) return false

        val p = Array(4) { LongArray(16) }
        val q = Array(4) { LongArray(16) }
        if (unpackneg(q, publicKey) != 0) return false

        val sha512 = MessageDigest.getInstance("SHA-512")
        sha512.update(signature, 0, 32)
        sha512.update(publicKey, 0, 32)
        sha512.update(message)
        val h = sha512.digest()
        reduce(h)

        scalarmult(p, q, h)
        scalarbase(q, signature, 32)
        add(p, q)

        val t = ByteArray(32)
        pack(t, p)
        return constantTimeEquals32(signature, t)
    }

    private fun isCanonicalScalar(buf: ByteArray, offset: Int): Boolean {
        // S < L (little-endian 32-byte unsigned compare)
        for (i in 31 downTo 0) {
            val sByte = buf[offset + i].toInt() and 0xff
            val lByte = L[i].toInt()
            if (sByte < lByte) return true
            if (sByte > lByte) return false
        }
        return false
    }

    private fun constantTimeEquals32(a: ByteArray, b: ByteArray): Boolean {
        var d = 0
        for (i in 0 until 32) {
            d = d or ((a[i].toInt() xor b[i].toInt()) and 0xff)
        }
        return d == 0
    }

    private fun set25519(r: LongArray, a: LongArray) {
        System.arraycopy(a, 0, r, 0, 16)
    }

    private fun car25519(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += 1L shl 16
            val c = o[i] shr 16
            if (i < 15) {
                o[i + 1] += c - 1L
            } else {
                o[0] += 38L * (c - 1L)
            }
            o[i] -= c shl 16
        }
    }

    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).inv().toLong()
        for (i in 0 until 16) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack25519(o: ByteArray, n: LongArray) {
        val m = LongArray(16)
        val t = LongArray(16)
        System.arraycopy(n, 0, t, 0, 16)
        car25519(t)
        car25519(t)
        car25519(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffedL
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffffL - ((m[i - 1] shr 16) and 1L)
                m[i - 1] = m[i - 1] and 0xffffL
            }
            m[15] = t[15] - 0x7fffL - ((m[14] shr 16) and 1L)
            val b = ((m[15] shr 16) and 1L).toInt()
            m[14] = m[14] and 0xffffL
            sel25519(t, m, 1 - b)
        }
        for (i in 0 until 16) {
            o[2 * i] = (t[i] and 0xffL).toByte()
            o[2 * i + 1] = ((t[i] shr 8) and 0xffL).toByte()
        }
    }

    private fun neq25519(a: LongArray, b: LongArray): Int {
        val c = ByteArray(32)
        val d = ByteArray(32)
        pack25519(c, a)
        pack25519(d, b)
        return if (constantTimeEquals32(c, d)) 0 else 1
    }

    private fun par25519(a: LongArray): Int {
        val d = ByteArray(32)
        pack25519(d, a)
        return d[0].toInt() and 1
    }

    private fun unpack25519(o: LongArray, n: ByteArray) {
        for (i in 0 until 16) {
            o[i] = (n[2 * i].toInt() and 0xff).toLong() + ((n[2 * i + 1].toInt() and 0xff).toLong() shl 8)
        }
        o[15] = o[15] and 0x7fffL
    }

    private fun A(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] + b[i]
    }

    private fun Z(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] - b[i]
    }

    private fun M(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) {
            for (j in 0 until 16) {
                t[i + j] += a[i] * b[j]
            }
        }
        for (i in 0 until 15) {
            t[i] += 38L * t[i + 16]
        }
        System.arraycopy(t, 0, o, 0, 16)
        car25519(o)
        car25519(o)
    }

    private fun S(o: LongArray, a: LongArray) {
        M(o, a, a)
    }

    private fun inv25519(o: LongArray, i: LongArray) {
        val c = i.copyOf(16)
        for (a in 253 downTo 0) {
            S(c, c)
            if (a != 2 && a != 4) M(c, c, i)
        }
        System.arraycopy(c, 0, o, 0, 16)
    }

    private fun pow2523(o: LongArray, i: LongArray) {
        val c = i.copyOf(16)
        for (a in 250 downTo 0) {
            S(c, c)
            if (a != 1) M(c, c, i)
        }
        System.arraycopy(c, 0, o, 0, 16)
    }

    private fun add(p: Array<LongArray>, q: Array<LongArray>) {
        val a = LongArray(16)
        val b = LongArray(16)
        val c = LongArray(16)
        val d = LongArray(16)
        val t = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)
        val g = LongArray(16)
        val h = LongArray(16)

        Z(a, p[1], p[0])
        Z(t, q[1], q[0])
        M(a, a, t)
        A(b, p[0], p[1])
        A(t, q[0], q[1])
        M(b, b, t)
        M(c, p[3], q[3])
        M(c, c, D2)
        M(d, p[2], q[2])
        A(d, d, d)
        Z(e, b, a)
        Z(f, d, c)
        A(g, d, c)
        A(h, b, a)

        M(p[0], e, f)
        M(p[1], h, g)
        M(p[2], g, f)
        M(p[3], e, h)
    }

    private fun cswap(p: Array<LongArray>, q: Array<LongArray>, b: Int) {
        for (i in 0 until 4) {
            sel25519(p[i], q[i], b)
        }
    }

    private fun pack(r: ByteArray, p: Array<LongArray>) {
        val tx = LongArray(16)
        val ty = LongArray(16)
        val zi = LongArray(16)
        inv25519(zi, p[2])
        M(tx, p[0], zi)
        M(ty, p[1], zi)
        pack25519(r, ty)
        r[31] = (r[31].toInt() xor (par25519(tx) shl 7)).toByte()
    }

    private fun scalarmult(p: Array<LongArray>, q: Array<LongArray>, s: ByteArray, sOff: Int = 0) {
        set25519(p[0], GF0)
        set25519(p[1], GF1)
        set25519(p[2], GF1)
        set25519(p[3], GF0)
        for (i in 255 downTo 0) {
            val b = ((s[sOff + (i ushr 3)].toInt() ushr (i and 7)) and 1)
            cswap(p, q, b)
            add(q, p)
            add(p, p)
            cswap(p, q, b)
        }
    }

    private fun scalarbase(p: Array<LongArray>, s: ByteArray, sOff: Int) {
        val q = Array(4) { LongArray(16) }
        set25519(q[0], X)
        set25519(q[1], Y)
        set25519(q[2], GF1)
        M(q[3], X, Y)
        scalarmult(p, q, s, sOff)
    }

    private fun unpackneg(r: Array<LongArray>, p: ByteArray): Int {
        val t = LongArray(16)
        val chk = LongArray(16)
        val num = LongArray(16)
        val den = LongArray(16)
        val den2 = LongArray(16)
        val den4 = LongArray(16)
        val den6 = LongArray(16)

        set25519(r[2], GF1)
        unpack25519(r[1], p)
        S(num, r[1])
        M(den, num, D)
        Z(num, num, r[2])
        A(den, r[2], den)

        S(den2, den)
        S(den4, den2)
        M(den6, den4, den2)
        M(t, den6, num)
        M(t, t, den)

        pow2523(t, t)
        M(t, t, num)
        M(t, t, den)
        M(t, t, den)
        M(r[0], t, den)

        S(chk, r[0])
        M(chk, chk, den)
        if (neq25519(chk, num) != 0) {
            M(r[0], r[0], I)
        }
        S(chk, r[0])
        M(chk, chk, den)
        if (neq25519(chk, num) != 0) {
            return -1
        }
        if (par25519(r[0]) == ((p[31].toInt() ushr 7) and 1)) {
            Z(r[0], GF0, r[0])
        }
        M(r[3], r[0], r[1])
        return 0
    }

    private fun reduce(r: ByteArray) {
        val x = LongArray(64)
        for (i in 0 until 64) x[i] = (r[i].toInt() and 0xff).toLong()
        modL(r, x)
    }

    private fun modL(r: ByteArray, x: LongArray) {
        for (i in 63 downTo 32) {
            var carry = 0L
            for (j in i - 32 until i - 12) {
                x[j] += carry - 16L * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128L) shr 8
                x[j] -= carry shl 8
            }
            x[i - 12] += carry
            x[i] = 0L
        }
        var carry = 0L
        for (j in 0 until 32) {
            x[j] += carry - (x[31] shr 4) * L[j]
            carry = x[j] shr 8
            x[j] = x[j] and 255L
        }
        for (j in 0 until 32) {
            x[j] -= carry * L[j]
        }
        for (i in 0 until 32) {
            x[i + 1] += x[i] shr 8
            r[i] = (x[i] and 255L).toByte()
        }
    }
}
