package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NodeUrlNormalizerTest {
    @Test
    fun httpsNodeDerivesWssEndpoint() {
        val endpoint = NodeUrlNormalizer.normalize("https://mirage.example.com").getOrThrow()

        assertEquals("https://mirage.example.com", endpoint.apiBaseUrl)
        assertEquals("wss://mirage.example.com", endpoint.wsBaseUrl)
        assertEquals("mirage.example.com", endpoint.displayHost)
    }

    @Test
    fun hostWithoutSchemeDefaultsToHttps() {
        val endpoint = NodeUrlNormalizer.normalize("10.0.2.2:8080").getOrThrow()

        assertEquals("https://10.0.2.2:8080", endpoint.apiBaseUrl)
        assertEquals("wss://10.0.2.2:8080", endpoint.wsBaseUrl)
    }

    @Test
    fun websocketSchemeDerivesHttpApiEndpoint() {
        val endpoint = NodeUrlNormalizer.normalize("ws://127.0.0.1:8080/mirage").getOrThrow()

        assertEquals("http://127.0.0.1:8080/mirage", endpoint.apiBaseUrl)
        assertEquals("ws://127.0.0.1:8080/mirage", endpoint.wsBaseUrl)
    }

    @Test
    fun unsupportedSchemeFails() {
        val result = NodeUrlNormalizer.normalize("ftp://mirage.example.com")

        assertTrue(result.isFailure)
    }
}
