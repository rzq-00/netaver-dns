package com.netaver.dns.dns

import android.net.VpnService

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * DNS-over-HTTPS (RFC 8484): HTTP/1.1 POST with application/dns-message
 * over a persistent TLS connection (port 443). Manual HTTP framing so the
 * socket can be protect()ed from the VPN.
 */
class DohUpstream : TlsUpstream {

    private val path: String

    constructor(vpn: VpnService, ip: String, tlsHost: String) :
            this(vpn, ip, tlsHost, 443, "/dns-query")

    constructor(vpn: VpnService, ip: String, tlsHost: String, port: Int, path: String?) :
            super(vpn, ip, tlsHost, port) {
        this.path = if (path.isNullOrEmpty()) "/dns-query" else path
    }

    @Throws(IOException::class)
    override fun query(q: ByteArray, qlen: Int): ByteArray {
        ensure()
        try {
            val out: OutputStream = out()
            val input: InputStream = `in`()
            val req = "POST " + path + " HTTP/1.1\r\n" +
                    "Host: " + tlsHost + "\r\n" +
                    "Content-Type: application/dns-message\r\n" +
                    "Accept: application/dns-message\r\n" +
                    "Content-Length: " + qlen + "\r\n" +
                    "Connection: keep-alive\r\n" +
                    "\r\n"
            out.write(req.toByteArray(StandardCharsets.US_ASCII))
            out.write(q, 0, qlen)
            out.flush()
            return readResponse(input)
        } catch (e: IOException) {
            onFailure(e)
            throw e
        }
    }

    private fun readResponse(input: InputStream): ByteArray {
        val status = readLine(input)
        if (!status.contains(" 200 ")) throw IOException("DoH status: $status")
        var contentLength = -1
        var chunked = false
        var line = ""
        while (readLine(input).also { line = it }.isNotEmpty()) {
            val l = line.lowercase()
            if (l.startsWith("content-length:")) {
                try { contentLength = l.substring(15).trim().toInt() } catch (_: NumberFormatException) {}
            } else if (l.startsWith("transfer-encoding:") && l.contains("chunked")) {
                chunked = true
            }
        }
        val body = ByteArrayOutputStream()
        if (chunked) {
            while (true) {
                val hex = readLine(input).trim().split(";")[0]
                val n = hex.toIntOrNull(16)
                    ?: throw IOException("DoH: bad chunk size")
                if (n == 0) {
                    // B8: consume trailer headers after the terminal
                    // chunk (RFC 7230: trailers end at a blank line).
                    // Reading exactly one line left trailer bytes in the
                    // stream, desyncing the next response parsed on this
                    // persistent connection.
                    try {
                        while (readLine(input).isNotEmpty()) { /* trailers ignored */ }
                    } catch (e: EOFException) {
                        // body already complete; the stream is done either way
                    }
                    break
                }
                // cap: same bound as the Content-Length path (no 2GB chunk OOM)
                if (n > 65535 || body.size() + n > 65535)
                    throw IOException("DoH chunk too large")
                copyN(input, body, n)
                readLine(input) // trailing CRLF
            }
        } else if (contentLength >= 0) {
            if (contentLength > 65535) throw IOException("DoH body too large")
            copyN(input, body, contentLength)
        } else {
            throw IOException("DoH: no content length")
        }
        return body.toByteArray()
    }

    companion object {
        private fun copyN(input: InputStream, out: ByteArrayOutputStream, n: Int) {
            val buf = ByteArray(2048)
            var remaining = n
            while (remaining > 0) {
                val r = input.read(buf, 0, minOf(buf.size, remaining))
                if (r < 0) throw IOException("DoH body truncated")
                out.write(buf, 0, r)
                remaining -= r
            }
        }
    }
}
