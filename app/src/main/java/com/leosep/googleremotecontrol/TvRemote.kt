package com.leosep.googleremotecontrol

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.math.BigInteger
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

/** Minimal hand-written protobuf (only what is needed). */
object Pb {
    fun varint(v: Long): ByteArray {
        val o = ByteArrayOutputStream(); var x = v
        while (x > 0x7F) { o.write(((x and 0x7F) or 0x80).toInt()); x = x ushr 7 }
        o.write(x.toInt()); return o.toByteArray()
    }
    private fun tag(f: Int, w: Int) = varint(((f shl 3) or w).toLong())
    fun int(f: Int, v: Int) = tag(f, 0) + varint(v.toLong())
    fun bytes(f: Int, b: ByteArray) = tag(f, 2) + varint(b.size.toLong()) + b
    fun str(f: Int, s: String) = bytes(f, s.toByteArray())

    fun parse(b: ByteArray): Map<Int, List<Any>> {
        val m = HashMap<Int, MutableList<Any>>(); var i = 0
        fun rv(): Long { var r = 0L; var s = 0
            while (true) { val x = b[i++].toInt() and 0xFF; r = r or ((x and 0x7F).toLong() shl s); if (x < 0x80) return r; s += 7 } }
        while (i < b.size) {
            val t = rv().toInt(); val f = t ushr 3
            val v: Any = when (t and 7) {
                0 -> rv()
                2 -> { val l = rv().toInt(); if (i + l > b.size) return m; val a = b.copyOfRange(i, i + l); i += l; a }
                1 -> { i += 8; 0L }
                5 -> { i += 4; 0L }
                else -> return m
            }
            m.getOrPut(f) { mutableListOf() }.add(v)
        }
        return m
    }
    fun read(ins: InputStream): ByteArray {
        var len = 0L; var s = 0
        while (true) { val x = ins.read(); if (x < 0) throw java.io.EOFException("Connection closed")
            len = len or ((x and 0x7F).toLong() shl s); if (x < 0x80) break; s += 7 }
        val buf = ByteArray(len.toInt()); var n = 0
        while (n < buf.size) { val r = ins.read(buf, n, buf.size - n); if (r < 0) throw java.io.EOFException(); n += r }
        return buf
    }
    fun frame(m: ByteArray) = varint(m.size.toLong()) + m
}

object K {
    const val UP = 19; const val DOWN = 20; const val LEFT = 21; const val RIGHT = 22; const val OK = 23
    const val BACK = 4; const val HOME = 3; const val MENU = 82; const val POWER = 26
    const val VOL_UP = 24; const val VOL_DOWN = 25; const val MUTE = 164
    const val ASSIST = 219; const val PLAY_PAUSE = 85; const val CH_UP = 166; const val CH_DOWN = 167
    const val DEL = 67; const val ENTER = 66; const val TAB = 61; const val SPACE = 62

    fun forChar(c: Char): Int? = when (c) {
        in 'a'..'z' -> 29 + (c - 'a')
        in 'A'..'Z' -> 29 + (c - 'A')
        in '0'..'9' -> 7 + (c - '0')
        '\n', '\r' -> ENTER
        '\t' -> TAB
        ' ' -> SPACE
        '.' -> 56; ',' -> 55; '-' -> 69; '=' -> 70; '/' -> 76
        ';' -> 74; '\'' -> 75; '@' -> 77; '+' -> 81; '*' -> 17; '#' -> 18
        '\\' -> 73; '[' -> 71; ']' -> 72; '`' -> 68
        else -> null
    }
}

class TvRemote(private val ctx: Context) {
    var onStatus: (String) -> Unit = {}
    @Volatile private var sock: SSLSocket? = null
    @Volatile private var gen = 0
    @Volatile private var scanGen = 0
    private var discovery: NsdManager? = null
    private var listener: NsdManager.DiscoveryListener? = null
    private val ex = Executors.newSingleThreadExecutor()
    private val pw = "changeit".toCharArray()

    private fun keyStore(): KeyStore {
        val f = File(ctx.filesDir, "client.p12")
        val ks = KeyStore.getInstance("PKCS12")
        if (f.exists()) { f.inputStream().use { ks.load(it, pw) }; return ks }
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = X500Name("CN=GoogleRemoteControl"); val now = Date()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now.time), now,
            Date(now.time + 3650L * 86400000), name, kp.public)
            .build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))
        val cert = JcaX509CertificateConverter().getCertificate(holder)
        ks.load(null, null); ks.setKeyEntry("k", kp.private, pw, arrayOf(cert))
        f.outputStream().use { ks.store(it, pw) }
        return ks
    }

    private fun socket(host: String, port: Int): SSLSocket {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keyStore(), pw) }
        // The TV presents a self-signed certificate during pairing, so all certs must be accepted.
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        }
        val sc = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, arrayOf(trustAll), null) }
        fun open(protocols: Array<String>?): SSLSocket {
            val s = sc.socketFactory.createSocket() as SSLSocket
            if (protocols != null) s.enabledProtocols = protocols
            s.connect(InetSocketAddress(host, port), 5000)
            s.soTimeout = 0
            return s
        }
        // The Android TV Remote Service only speaks TLS 1.2, but fall back to the platform default if needed.
        val s = open(arrayOf("TLSv1.2"))
        try {
            s.startHandshake()
            return s
        } catch (e: SSLException) {
            try { s.close() } catch (_: Exception) {}
            val s2 = open(null)
            s2.startHandshake()
            return s2
        }
    }

    /** Turns low-level network/SSL exceptions into messages a user can act on. */
    fun friendlyError(e: Throwable): String = when {
        e is SSLException -> "Secure handshake failed. Pair with the TV first (tap Pair) and try again."
        e is java.net.SocketTimeoutException -> "Connection timed out. Check the TV is on and on the same Wi-Fi."
        e is java.net.ConnectException -> "Could not reach the TV at that address."
        e is java.net.UnknownHostException -> "Unknown address."
        else -> e.message ?: "Connection failed"
    }

    private fun mod(n: BigInteger): ByteArray { val a = n.toByteArray(); return if (a[0] == 0.toByte()) a.copyOfRange(1, a.size) else a }

    /** Pairing (blocking). askCode must return the 6-character code shown on the TV. */
    fun pair(host: String, askCode: () -> String, status: (String) -> Unit) {
        status("Contacting TV…")
        val s = socket(host, 6467); val i = s.inputStream; val o = s.outputStream
        fun tx(p: ByteArray) { o.write(Pb.frame(Pb.int(1, 2) + Pb.int(2, 200) + p)); o.flush() }
        val enc = Pb.int(1, 3) + Pb.int(2, 4) // hexadecimal, 4 symbols
        tx(Pb.bytes(10, Pb.str(1, "androidtv-remote") + Pb.str(2, "GoogleRemoteControl"))); Pb.read(i)
        tx(Pb.bytes(20, Pb.bytes(1, enc) + Pb.int(3, 1))); Pb.read(i)
        tx(Pb.bytes(30, Pb.bytes(1, enc) + Pb.int(2, 1))); Pb.read(i)
        status("Enter the code shown on the TV")
        val raw = askCode().trim().uppercase()
        if (raw.length != 6) error("The code must be 6 characters")
        val hex = raw.substring(2)
        if (!hex.all { it in "0123456789ABCDEF" }) error("Invalid code")
        val mine = keyStore().getCertificate("k").publicKey as RSAPublicKey
        val theirs = s.session.peerCertificates[0].publicKey as RSAPublicKey
        val h = MessageDigest.getInstance("SHA-256")
        h.update(mod(mine.modulus)); h.update(mod(mine.publicExponent))
        h.update(mod(theirs.modulus)); h.update(mod(theirs.publicExponent))
        h.update(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        tx(Pb.bytes(40, Pb.bytes(1, h.digest())))
        val r = Pb.parse(Pb.read(i)); s.close()
        if ((r[2]?.firstOrNull() as? Long) != 200L) error("Wrong code")
        status("Paired ✔")
    }

    fun connect(host: String) {
        disconnect(); onStatus("Connecting…")
        val my = ++gen
        Thread {
            try {
                val s = socket(host, 6466); sock = s; val i = s.inputStream
                if (my != gen) { s.close(); return@Thread }
                onStatus("Connected")
                while (my == gen) {
                    val m = Pb.parse(Pb.read(i))
                    when {
                        m.containsKey(1) -> send(Pb.bytes(1, Pb.int(1, 622) + Pb.bytes(2,
                            Pb.str(1, "GoogleRemoteControl") + Pb.str(2, "GoogleRemoteControl") + Pb.int(3, 1) + Pb.str(4, "1") +
                                Pb.str(5, "androidtv.remote") + Pb.str(6, "1.0.0"))))
                        m.containsKey(2) -> send(Pb.bytes(2, Pb.int(1, 622)))
                        m.containsKey(8) -> {
                            val v = Pb.parse(m[8]!![0] as ByteArray)[1]?.firstOrNull() as? Long ?: 0L
                            send(Pb.bytes(9, Pb.int(1, v.toInt())))
                        }
                    }
                }
            } catch (e: Exception) {
                if (my == gen) onStatus("Disconnected: ${friendlyError(e)}")
            }
        }.start()
    }

    fun disconnect() {
        gen++
        try { sock?.close() } catch (_: Exception) {}
        sock = null
    }

    private fun send(msg: ByteArray) = ex.execute {
        try { sock?.outputStream?.apply { write(Pb.frame(msg)); flush() } } catch (_: Exception) {}
    }
    fun key(code: Int) = send(Pb.bytes(10, Pb.int(1, code) + Pb.int(2, 3))) // 3 = short press
    fun type(t: String) = t.forEach { c -> K.forChar(c)?.let { key(it) } }
    fun openLink(url: String) = send(Pb.bytes(90, Pb.str(1, url)))

    /**
     * Discovers TVs on the local network in two ways:
     *  - mDNS/NSD lookup of `_androidtvremote2._tcp`
     *  - a parallel TCP scan of the local /24 subnet on port 6466
     * [onDevice] is called for every device found, [onDone] once the subnet scan finishes.
     */
    fun discover(onDevice: (String, String) -> Unit, onDone: () -> Unit) {
        stopDiscovery()
        val g = ++scanGen
        startNsd(g, onDevice)
        Thread {
            scanSubnet(g, onDevice)
            if (g == scanGen) onDone()
        }.start()
    }

    private fun startNsd(g: Int, onDevice: (String, String) -> Unit) {
        val nsd = ctx.getSystemService(Context.NSD_SERVICE) as NsdManager
        discovery = nsd
        val l = object : NsdManager.DiscoveryListener {
            override fun onServiceFound(s: NsdServiceInfo) {
                try {
                    nsd.resolveService(s, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(i: NsdServiceInfo, e: Int) {}
                        @Suppress("DEPRECATION")
                        override fun onServiceResolved(i: NsdServiceInfo) {
                            val addr = i.host?.hostAddress ?: return
                            if (g == scanGen) onDevice(i.serviceName, addr)
                        }
                    })
                } catch (_: Exception) {}
            }
            override fun onStartDiscoveryFailed(t: String, e: Int) {}
            override fun onStopDiscoveryFailed(t: String, e: Int) {}
            override fun onDiscoveryStarted(t: String) {}
            override fun onDiscoveryStopped(t: String) {}
            override fun onServiceLost(s: NsdServiceInfo) {}
        }
        listener = l
        try { nsd.discoverServices("_androidtvremote2._tcp", NsdManager.PROTOCOL_DNS_SD, l) } catch (_: Exception) {}
    }

    private fun localIpv4(): String? {
        try {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                if (!ni.isUp || ni.isLoopback) continue
                for (ia in ni.inetAddresses) {
                    if (ia is Inet4Address && !ia.isLoopbackAddress && ia.isSiteLocalAddress) return ia.hostAddress
                }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun scanSubnet(g: Int, onDevice: (String, String) -> Unit) {
        val own = localIpv4() ?: return
        val base = own.substringBeforeLast('.')
        val pool = Executors.newFixedThreadPool(48)
        val latch = CountDownLatch(254)
        for (i in 1..254) {
            val target = "$base.$i"
            pool.execute {
                try {
                    if (target != own && g == scanGen) {
                        Socket().use { it.connect(InetSocketAddress(target, 6466), 400) }
                        if (g == scanGen) onDevice("Android TV", target)
                    }
                } catch (_: Exception) {} finally { latch.countDown() }
            }
        }
        latch.await(20, TimeUnit.SECONDS)
        pool.shutdownNow()
    }

    fun stopDiscovery() {
        scanGen++
        try { listener?.let { discovery?.stopServiceDiscovery(it) } } catch (_: Exception) {}
        listener = null
    }
}
