package com.netaver.dns.dns

import android.net.VpnService

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** Plain DNS over UDP (port 53). */
class PlainUpstream(vpn: VpnService, ip: String) : DnsUpstream {
    private val sock: DatagramSocket
    private val server: InetAddress
    private val respBuf = ByteArray(2048)

    init {
        sock = DatagramSocket()
        vpn.protect(sock)
        sock.soTimeout = 3000
        server = InetAddress.getByName(ip)
    }

    @Synchronized
    @Throws(IOException::class)
    override fun query(q: ByteArray, qlen: Int): ByteArray {
        sock.send(DatagramPacket(q, qlen, server, 53))
        val incoming = DatagramPacket(respBuf, respBuf.size)
        sock.receive(incoming)
        val resp = ByteArray(incoming.length)
        System.arraycopy(respBuf, 0, resp, 0, resp.size)
        return resp
    }

    override fun close() {
        try { sock.close() } catch (_: Exception) {}
    }
}
