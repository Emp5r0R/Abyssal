package com.abyssal.chat.data.network

import java.net.InetAddress
import java.net.UnknownHostException
import okhttp3.Dns
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PublicNodeDnsTest {
    @Test
    fun productionAllowsOnlyEntirelyPublicResolutionSets() {
        val public = address(93, 184, 216, 34)
        val private = address(10, 0, 0, 4)
        assertEquals(listOf(public), PublicNodeDns(false, fixed(public)).lookup("node.example.com"))
        assertThrows(UnknownHostException::class.java) {
            PublicNodeDns(false, fixed(public, private)).lookup("node.example.com")
        }
        assertThrows(UnknownHostException::class.java) {
            PublicNodeDns(false, fixed(private)).lookup("node.example.com")
        }
    }

    @Test
    fun productionRejectsDevelopmentHostsWithoutResolvingThem() {
        val never = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                throw AssertionError("delegate must not run")
        }
        for (host in listOf("localhost", "127.0.0.1", "::1", "10.0.2.2")) {
            assertThrows(UnknownHostException::class.java) {
                PublicNodeDns(false, never).lookup(host)
            }
        }
    }

    @Test
    fun developmentAcceptsOnlyTheExactAddressForItsLocator() {
        val loopback = address(127, 0, 0, 1)
        val emulator = address(10, 0, 2, 2)
        assertEquals(listOf(loopback), PublicNodeDns(true, fixed(loopback)).lookup("localhost"))
        assertEquals(listOf(emulator), PublicNodeDns(true, fixed(emulator)).lookup("10.0.2.2"))
        assertThrows(UnknownHostException::class.java) {
            PublicNodeDns(true, fixed(address(127, 0, 0, 2))).lookup("127.0.0.1")
        }
    }

    @Test
    fun reservedIpv4AndIpv6RangesFailClosed() {
        for (value in listOf(
            "100.64.0.1",
            "169.254.169.254",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "2002:0a00:0001::1"
        )) {
            assertThrows(UnknownHostException::class.java) {
                PublicNodeDns(false, fixed(InetAddress.getByName(value))).lookup("node.example.com")
            }
        }
    }

    private fun fixed(vararg addresses: InetAddress): Dns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = addresses.toList()
    }

    private fun address(a: Int, b: Int, c: Int, d: Int): InetAddress = InetAddress.getByAddress(
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())
    )
}
