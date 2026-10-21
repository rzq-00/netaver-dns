package com.netaver.dns.dns

import android.net.VpnService
import android.util.Log

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.util.Collections

import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Shared TLS socket logic for DoT/DoH. Persistent connection with
 * reconnect-on-failure (battery-friendly: no handshake per query).
 */
abstract class TlsUpstream protected constructor(
    protected val vpn: VpnService,
    protected val ip: String,
    protected val tlsHost: String,
    protected val port: Int
) : DnsUpstream {

    private var sock: SSLSocket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null

    @Synchronized
    @Throws(IOException::class)
    protected fun ensure() {
        val s0 = sock
        if (s0 != null && s0.isConnected && !s0.isClosed
                && !s0.isInputShutdown && !s0.isOutputShutdown) return
        closeQuiet()
        val sf = SSLSocketFactory.getDefault() as SSLSocketFactory
        val s = sf.createSocket() as SSLSocket
        vpn.protect(s)
        s.connect(InetSocketAddress(ip, port), 5000)
        val params: SSLParameters = s.sslParameters
        params.serverNames = Collections.singletonList(SNIHostName(tlsHost))
        params.endpointIdentificationAlgorithm = "HTTPS"
        s.sslParameters = params
        s.soTimeout = 5000
        s.startHandshake()
        sock = s
        input = s.inputStream
        output = s.outputStream
    }

    @Synchronized
    protected fun `in`(): InputStream = input!!

    @Synchronized
    protected fun out(): OutputStream = output!!

    private fun closeQuiet() {
        val s = sock
        if (s != null) {
            try { s.close() } catch (_: Exception) {}
            sock = null
            input = null
            output = null
        }
    }

    @Synchronized
    override fun close() {
        closeQuiet()
    }

    protected fun onFailure(e: IOException) {
        Log.d(TAG, "tls upstream failure, will reconnect", e)
        closeQuiet()
    }

    companion object {
        private const val TAG = "TlsUpstream"

        @JvmStatic
        protected fun readFully(input: InputStream, b: ByteArray, len: Int) {
            var off = 0
            while (off < len) {
                val n = input.read(b, off, len - off)
                if (n < 0) throw EOFException()
                off += n
            }
        }

        /** Read an ASCII line terminated by \n (headers). */
        @JvmStatic
        protected fun readLine(input: InputStream): String {
            val sb = StringBuilder(128)
            var c = 0
            while (input.read().also { c = it } >= 0) {
                if (c == '\n'.code) break
                if (c != '\r'.code) sb.append(c.toChar())
                if (sb.length > 8192) throw IOException("header too long")
            }
            if (c < 0 && sb.isEmpty()) throw EOFException()
            return sb.toString()
        }
    }
}
