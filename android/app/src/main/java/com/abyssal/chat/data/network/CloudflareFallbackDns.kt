package com.abyssal.chat.data.network

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import okhttp3.Dns
import kotlin.random.Random

class CloudflareFallbackDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val normalizedHost = IDN.toASCII(hostname.trim())
        if (normalizedHost.isBlank()) throw UnknownHostException(hostname)

        val systemFailure = runCatching { Dns.SYSTEM.lookup(normalizedHost) }
        systemFailure.getOrNull()
            ?.takeIf { it.isNotEmpty() }
            ?.let { return it }

        val fallback = listOf("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
            .flatMap { resolver ->
                queryUdp(resolver, normalizedHost, 1) + queryUdp(resolver, normalizedHost, 28)
            }
            .distinctBy { it.hostAddress }

        if (fallback.isNotEmpty()) return fallback

        throw systemFailure.exceptionOrNull() as? UnknownHostException
            ?: UnknownHostException(hostname)
    }

    private fun queryUdp(resolverIp: String, hostname: String, recordType: Int): List<InetAddress> {
        val txId = Random.nextInt(0, 65536)
        val query = buildQuery(txId, hostname, recordType)
        return runCatching {
            DatagramSocket().use { socket ->
                socket.soTimeout = 2500
                socket.send(
                    DatagramPacket(
                        query,
                        query.size,
                        InetSocketAddress(InetAddress.getByName(resolverIp), 53)
                    )
                )
                val buffer = ByteArray(1500)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                parseResponse(buffer.copyOf(response.length), txId)
            }
        }.getOrElse { error ->
            if (error is SocketTimeoutException) emptyList() else emptyList()
        }
    }

    private fun buildQuery(txId: Int, hostname: String, recordType: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xff)
        out.write(txId and 0xff)
        out.write(0x01)
        out.write(0x00)
        out.write(0x00)
        out.write(0x01)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        hostname.split('.').forEach { label ->
            val bytes = label.encodeToByteArray()
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
        out.write((recordType ushr 8) and 0xff)
        out.write(recordType and 0xff)
        out.write(0x00)
        out.write(0x01)
        return out.toByteArray()
    }

    private fun parseResponse(packet: ByteArray, expectedTxId: Int): List<InetAddress> {
        if (packet.size < 12) return emptyList()
        val txId = readU16(packet, 0)
        if (txId != expectedTxId) return emptyList()

        val questionCount = readU16(packet, 4)
        val answerCount = readU16(packet, 6)
        var offset = 12
        repeat(questionCount) {
            offset = skipName(packet, offset)
            offset += 4
            if (offset > packet.size) return emptyList()
        }

        val addresses = mutableListOf<InetAddress>()
        repeat(answerCount) {
            offset = skipName(packet, offset)
            if (offset + 10 > packet.size) return addresses
            val type = readU16(packet, offset)
            val dataLength = readU16(packet, offset + 8)
            offset += 10
            if (offset + dataLength > packet.size) return addresses

            if ((type == 1 && dataLength == 4) || (type == 28 && dataLength == 16)) {
                addresses += InetAddress.getByAddress(packet.copyOfRange(offset, offset + dataLength))
            }
            offset += dataLength
        }
        return addresses
    }

    private fun skipName(packet: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        while (offset < packet.size) {
            val length = packet[offset].toInt() and 0xff
            if (length == 0) return offset + 1
            if ((length and 0xc0) == 0xc0) return offset + 2
            offset += length + 1
        }
        return packet.size
    }

    private fun readU16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
    }
}
