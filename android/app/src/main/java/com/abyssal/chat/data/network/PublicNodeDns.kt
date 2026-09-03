package com.abyssal.chat.data.network

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale
import okhttp3.Dns

/** Rejects DNS rebinding into local/private/reserved networks at connect time. */
class PublicNodeDns(
    private val allowDevelopmentLoopback: Boolean,
    private val delegate: Dns = Dns.SYSTEM
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val normalizedHost = hostname.lowercase(Locale.ROOT)
        val developmentHost = normalizedHost in DEVELOPMENT_HOSTS
        if (developmentHost && !allowDevelopmentLoopback) {
            throw UnknownHostException("Node address rejected")
        }
        val addresses = delegate.lookup(hostname)
        if (addresses.isEmpty() || if (developmentHost) {
                addresses.any { !isExpectedDevelopmentAddress(normalizedHost, it) }
            } else {
                addresses.any { !isPublic(it) }
            }
        ) {
            throw UnknownHostException("Node address rejected")
        }
        return addresses
    }

    private fun isExpectedDevelopmentAddress(host: String, address: InetAddress): Boolean = when (host) {
        "localhost" -> address.isLoopbackAddress
        "127.0.0.1" -> address.address.contentEquals(byteArrayOf(127, 0, 0, 1))
        "::1" -> address.isLoopbackAddress && address is Inet6Address
        "10.0.2.2" -> address.address.contentEquals(byteArrayOf(10, 0, 2, 2))
        else -> false
    }

    private fun isPublic(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress) return false
        return when (address) {
            is Inet4Address -> publicIpv4(address.address)
            is Inet6Address -> publicIpv6(address.address)
            else -> false
        }
    }

    private fun publicIpv4(bytes: ByteArray): Boolean {
        val first = bytes[0].toInt() and 0xff
        val second = bytes[1].toInt() and 0xff
        return when {
            first == 0 || first == 10 || first == 127 || first >= 224 -> false
            first == 100 && second in 64..127 -> false
            first == 169 && second == 254 -> false
            first == 172 && second in 16..31 -> false
            first == 192 && second == 0 -> false
            first == 192 && second == 168 -> false
            first == 192 && second == 88 && (bytes[2].toInt() and 0xff) == 99 -> false
            first == 198 && second in 18..19 -> false
            first == 198 && second == 51 && (bytes[2].toInt() and 0xff) == 100 -> false
            first == 203 && second == 0 && (bytes[2].toInt() and 0xff) == 113 -> false
            else -> true
        }
    }

    private fun publicIpv6(bytes: ByteArray): Boolean {
        val first = bytes[0].toInt() and 0xff
        val second = bytes[1].toInt() and 0xff
        if (first !in 0x20..0x3f) return false
        if (first == 0x20 && second == 0x01) {
            val third = bytes[2].toInt() and 0xff
            val fourth = bytes[3].toInt() and 0xff
            if ((third == 0x0d && fourth == 0xb8) || third == 0x00 || third == 0x02) return false
        }
        // 6to4 embeds an IPv4 route and can otherwise hide a private target.
        return !(first == 0x20 && second == 0x02)
    }

    private companion object {
        val DEVELOPMENT_HOSTS = setOf("localhost", "127.0.0.1", "::1", "10.0.2.2")
    }
}
