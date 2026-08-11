package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.ChatSession
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RealChatTransportSecurityTest {
    @Test
    fun oversizedInboundTextClosesWithPolicyViolationAndDisconnects() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()

        assertFalse(
            transport.disconnectForOversizedTextFrame(
                socket,
                "x".repeat(1 * 1024 * 1024),
                "node-1"
            )
        )
        assertEquals(null, socket.closeCode)

        assertTrue(
            transport.disconnectForOversizedTextFrame(
                socket,
                "\u20ac".repeat(400_000),
                "node-1"
            )
        )
        assertEquals(1009, socket.closeCode)
        assertEquals("message too big", socket.closeReason)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun utf8LimitCountsMultibyteAndSurrogateInputWithoutAllocation() {
        assertFalse(exceedsUtf8ByteLimit("\u20ac".repeat(349_525), 1 * 1024 * 1024))
        assertTrue(exceedsUtf8ByteLimit("\u20ac".repeat(349_526), 1 * 1024 * 1024))
        assertFalse(exceedsUtf8ByteLimit("\ud83d\ude00", 4))
        assertTrue(exceedsUtf8ByteLimit("\ud83d\ude00", 3))
        assertFalse(exceedsUtf8ByteLimit("\ud83d", 1))
    }

    @Test
    fun websocketTicketResponseRejectsMalformedExtraAndOversizedBodies() {
        val ticket = "A".repeat(43)
        val valid = JSONObject()
            .put("ticket", ticket)
            .put("expires_in_sec", 15)
            .toString()
            .toByteArray()
        assertEquals(WsTicket(ticket, 15), parseWsTicketResponseBody(valid))
        val nonCanonicalTicket = ticket.dropLast(1) + "B"
        assertNull(
            parseWsTicketResponseBody(
                JSONObject().put("ticket", nonCanonicalTicket).put("expires_in_sec", 15)
                    .toString().toByteArray()
            )
        )

        assertNull(
            parseWsTicketResponseBody(
                JSONObject()
                    .put("ticket", ticket)
                    .put("expires_in_sec", 15)
                    .put("unexpected", true)
                    .toString()
                    .toByteArray()
            )
        )
        assertNull(
            parseWsTicketResponseBody(
                JSONObject().put("ticket", ticket).put("expires_in_sec", 15.5).toString().toByteArray()
            )
        )
        assertNull(parseWsTicketResponseBody(ByteArray(WS_TICKET_MAX_RESPONSE_BYTES + 1) { '{'.code.toByte() }))
    }

    @Test
    fun websocketUpgradeContainsOnlyShortTicketAndNeverBearer() {
        val ticket = "A".repeat(43)
        val endpoint = NodeEndpoint(
            inputUrl = "https://node.example",
            apiBaseUrl = "https://node.example",
            wsBaseUrl = "wss://node.example",
            displayHost = "node.example"
        )

        val request = websocketUpgradeRequest(endpoint, ticket)
        val protocols = request.header("Sec-WebSocket-Protocol")
        assertEquals("abyssal-v1, ticket.$ticket", protocols)
        assertFalse(protocols.orEmpty().contains("bearer."))
        assertNull(request.header("Authorization"))
    }

    @Test
    fun disconnectCancelsInFlightTicketAndBlocksLateUpgrade() = runBlocking {
        val factory = TicketCancellationCallFactory()
        val node = InMemoryNodeConfigService()
        val endpoint = NodeEndpoint(
            inputUrl = "http://127.0.0.1",
            apiBaseUrl = "http://127.0.0.1",
            wsBaseUrl = "ws://127.0.0.1",
            displayHost = "127.0.0.1"
        )
        node.setActiveSession(NodeSession(endpoint, "token-1", "node-1", 5))
        val transport = RealChatTransport(node, OkHttpClient(), factory)

        transport.connect()
        assertTrue(factory.call.enqueued.await(2, java.util.concurrent.TimeUnit.SECONDS))
        transport.disconnect()

        assertTrue(factory.call.cancelled)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun presenceCatalogRejectsOversizeSchemaTypesNoncanonicalAndCollisionsAtomically() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val valid = presence("Alice")
        assertEquals(1, with(transport) { JSONArray().put(valid).toPresenceCatalog()?.entries?.size })

        val malformed = JSONArray().put(presence("Alice")).put(presence("alice"))
        assertNull(with(transport) { malformed.toPresenceCatalog() })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("unexpected", true)).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").remove("connected")).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("connected", "true")).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(
                presence("Alice").put("identity_public_b64", "A".repeat(170) + "B")
            ).toPresenceCatalog()
        })
        val oversized = JSONArray()
        repeat(129) { oversized.put(presence("User$it")) }
        assertNull(with(transport) { oversized.toPresenceCatalog() })
    }

    @Test
    fun roomCatalogRejectsOversizeSchemaTypesRangesCollisionsAndPartialFrames() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertEquals(
            1,
            with(transport) { JSONArray().put(room()).toChatSessions(1024)?.size }
        )
        assertNull(with(transport) { JSONArray().put(room().remove("owner_username")).toChatSessions(1024) })
        assertNull(with(transport) {
            JSONArray().put(room().put("allow_images", "true")).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room().put("self_destruct_timer_sec", 86_401)).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room().put("name", "x".repeat(37))).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room("forum_alpha")).put(room("forum_ALPHA")).toChatSessions(1024)
        })
        val oversized = JSONArray()
        repeat(1025) { oversized.put(room("forum_room_$it")) }
        assertNull(with(transport) { oversized.toChatSessions(1024) })
        // A valid entry followed by a malformed one produces no partial result.
        assertNull(with(transport) {
            JSONArray().put(room()).put(room().put("overall_expiry_sec", 86_401)).toChatSessions(1024)
        })
    }

    @Test
    fun directCatalogRejectsOversizeSchemaTypesAndCaseCollisions() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertEquals(1, with(transport) { JSONArray().put(direct()).toDirectSessions()?.size })
        assertNull(with(transport) { JSONArray().put(direct().remove("peer_username")).toDirectSessions() })
        assertNull(with(transport) {
            JSONArray().put(direct().put("peer_username", 7)).toDirectSessions()
        })
        assertNull(with(transport) {
            JSONArray().put(direct("dm_alice", "Alice")).put(direct("dm_ALICE", "Bob"))
                .toDirectSessions()
        })
        assertNull(with(transport) {
            JSONArray().put(direct("dm_alice", "Alice")).put(direct("dm_bob", "alice"))
                .toDirectSessions()
        })
        val oversized = JSONArray()
        repeat(129) { oversized.put(direct("dm_user_$it", "User$it")) }
        assertNull(with(transport) { oversized.toDirectSessions() })
    }

    @Test
    fun inboundMessageRequiresPinnedStableIdentityAndAllowsPrekeyRotation() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val stable = ByteArray(128) { index -> if (index < 64) 1 else 2 }
        val rotated = stable.clone().also { it[100] = 9 }
        val forged = stable.clone().also { it[0] = 7 }
        fun frame(publicKey: ByteArray, username: String = "Alice") = JSONObject()
            .put("type", "message")
            .put("version", 7)
            .put("chat_id", "dm_alice")
            .put("message_id", "message-1")
            .put("nonce_b64", encode(ByteArray(12) { 3 }))
            .put("ciphertext_b64", encode(byteArrayOf(4)))
            .put("signature_b64", encode(ByteArray(64) { 5 }))
            .put("wrapped_key_b64", encode(byteArrayOf(6)))
            .put("sender_username", username)
            .put("sender_public_key_b64", encode(publicKey))
            .put("identity_public_b64", encode(publicKey))
            .put("prekey_id", "")
            .put("is_prekey", false)

        val aliceCatalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        }
        assertNotNull(aliceCatalog)
        assertTrue(with(transport) { acceptPresenceCatalog(aliceCatalog!!) })
        val accepted = with(transport) { frame(rotated).toIncomingPayload() }
        assertTrue(accepted != null)
        accepted!!.senderPublicKey.fill(0)
        accepted.identityPublicKey.fill(0)
        accepted.nonce.fill(0)
        accepted.ciphertext.fill(0)
        accepted.signature.fill(0)
        accepted.wrappedKey.fill(0)
        assertNull(with(transport) { frame(forged).toIncomingPayload() })
        assertNull(with(transport) { frame(stable, "Missing").toIncomingPayload() })

        // A historical pin is insufficient after the directory removes a user.
        // The current presence catalog must still bind the username to its key.
        val bobCatalog = with(transport) {
            JSONArray().put(presence("Bob")).toPresenceCatalog()
        }
        assertNotNull(bobCatalog)
        assertTrue(with(transport) { acceptPresenceCatalog(bobCatalog!!) })
        assertNull(with(transport) { frame(rotated).toIncomingPayload() })
        stable.fill(0)
        rotated.fill(0)
        forged.fill(0)
    }

    @Test
    fun dynamicCatalogEventsRespectCapsAndCaseCollisionRules() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_alpha")) })
        assertFalse(with(transport) { acceptDynamicRoom(roomSession("forum_ALPHA")) })
        repeat(1023) { index ->
            assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_room_$index")) })
        }
        assertFalse(with(transport) { acceptDynamicRoom(roomSession("forum_overflow")) })

        val directTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertTrue(with(directTransport) { acceptDynamicDirect(directSession("dm_alice", "Alice")) })
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_ALICE", "Alice"))
        })
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_bob", "alice"))
        })
        repeat(127) { index ->
            assertTrue(with(directTransport) {
                acceptDynamicDirect(directSession("dm_user_$index", "User$index"))
            })
        }
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_overflow", "Overflow"))
        })
    }

    private fun presence(username: String): JSONObject = JSONObject()
        .put("username", username)
        .put("connected", true)
        .put("identity_public_b64", encode(ByteArray(128) { 1 }))
        .put("identity_prekey_id", "prekey-1")
        .put("directory_digest", encode(ByteArray(32) { 2 }))

    private fun room(id: String = "forum_alpha"): JSONObject = JSONObject()
        .put("id", id)
        .put("name", "alpha")
        .put("owner_username", "Owner123")
        .put("self_destruct_timer_sec", 5)
        .put("overall_expiry_sec", 0)
        .put("allow_images", true)
        .put("allow_videos", true)
        .put("allow_files", true)
        .put("enforce_text_absolute_expiry", false)
        .put("image_read_timer_sec", 5)
        .put("image_overall_expiry_sec", 0)
        .put("enforce_image_absolute_expiry", false)
        .put("video_read_timer_sec", 5)
        .put("video_overall_expiry_sec", 0)
        .put("enforce_video_absolute_expiry", false)
        .put("file_read_timer_sec", 5)
        .put("file_overall_expiry_sec", 0)
        .put("enforce_file_absolute_expiry", false)

    private fun direct(id: String = "dm_alice", peer: String = "Alice"): JSONObject = JSONObject()
        .put("id", id)
        .put("peer_username", peer)

    private fun roomSession(id: String): ChatSession = ChatSession(
        id = id,
        name = "room",
        isForum = true,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = 5
    )

    private fun directSession(id: String, peer: String): ChatSession = ChatSession(
        id = id,
        name = peer,
        isForum = false,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = 5
    )

    private fun encode(bytes: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private class RecordingWebSocket : WebSocket {
        var closeCode: Int? = null
        var closeReason: String? = null
        var cancelled = false

        override fun request(): Request = Request.Builder().url("https://node.example/v1/ws").build()

        override fun queueSize(): Long = 0L

        override fun send(text: String): Boolean = true

        override fun send(bytes: ByteString): Boolean = true

        override fun close(code: Int, reason: String?): Boolean {
            closeCode = code
            closeReason = reason
            return true
        }

        override fun cancel() {
            cancelled = true
        }
    }

    private class TicketCancellationCallFactory : Call.Factory {
        val call = TicketCancellationCall()

        override fun newCall(request: Request): Call {
            assertEquals("POST", request.method)
            assertEquals("Bearer token-1", request.header("Authorization"))
            assertEquals("no-store", request.header("Cache-Control"))
            assertEquals(0L, request.body?.contentLength())
            assertTrue(request.url.encodedPath.endsWith("/v1/ws-ticket"))
            return call
        }
    }

    private class TicketCancellationCall : Call {
        private val request = Request.Builder().url("http://127.0.0.1/v1/ws-ticket").build()
        val enqueued = CountDownLatch(1)
        @Volatile var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            enqueued.countDown()
        }

        override fun cancel() {
            cancelled = true
        }

        override fun isExecuted(): Boolean = enqueued.count == 0L

        override fun isCanceled(): Boolean = cancelled

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = TicketCancellationCall()
    }
}
