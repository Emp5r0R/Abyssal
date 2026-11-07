package com.abyssal.chat.data.storage

import com.abyssal.chat.domain.model.DeviceStoreSnapshot
import com.abyssal.chat.domain.model.Message
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class EncryptedDeviceStoreTest {
    private class FakeSecrets : LocalSecretStore {
        var secret: ByteArray? = null
        var destroyed = 0
        override fun getOrCreate(): ByteArray = (secret ?: ByteArray(32) { 7 }.also { secret = it }).copyOf()
        override fun destroy() { secret = null; destroyed++ }
    }

    private fun share(fill: Int) = ByteArray(32) { fill.toByte() }

    private fun snapshot() = DeviceStoreSnapshot(
        messages = mapOf(
            "dm_alice" to listOf(
                Message(
                    id = "m1", sender = "acct_alice", receiver = "You", content = "secret plan", timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = 0, reactions = mapOf("👍" to listOf("acct_bob")), editedAtMs = 5L
                ),
                Message(
                    id = "m2", sender = "You", receiver = "acct_alice", content = "Voice message.wav", timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = 0, isMedia = true, mediaType = "FILE", attachmentId = "att_1", attachmentCipherVersion = 2,
                    attachmentKey = ByteArray(32) { 3 }, attachmentName = "Voice message.wav", attachmentMimeType = "audio/wav",
                    attachmentSizeBytes = 1000, voiceDurationMs = 4_000
                )
            )
        ),
        roomNames = mapOf("forum_abc" to "Weekend plans"),
        displayNames = mapOf("acct_alice" to "Alice")
    )

    @Test
    fun keyNeedsBothTheDeviceSecretAndTheRelayShare() {
        val local = ByteArray(32) { 1 }
        val base = DeviceStoreCrypto.deriveKey(local, share(2), "node", "acct_me")
        assertEquals(32, base.size)
        assertFalse(base.contentEquals(DeviceStoreCrypto.deriveKey(local, share(3), "node", "acct_me")))
        assertFalse(base.contentEquals(DeviceStoreCrypto.deriveKey(ByteArray(32) { 9 }, share(2), "node", "acct_me")))
        assertFalse(base.contentEquals(DeviceStoreCrypto.deriveKey(local, share(2), "other-node", "acct_me")))
        assertArrayEquals(base, DeviceStoreCrypto.deriveKey(local, share(2), "node", "ACCT_ME"))
        assertNotEquals(DeviceStoreCrypto.fileName("node", "acct_me"), DeviceStoreCrypto.fileName("node", "acct_you"))
        assertFalse(DeviceStoreCrypto.fileName("node", "acct_me").contains("acct"))
    }

    @Test
    fun sealedDataOpensOnlyWithTheSameKeyAndContext() {
        val key = ByteArray(32) { 4 }
        val aad = DeviceStoreCrypto.context("node", "acct_me")
        val sealed = DeviceStoreCrypto.seal(key, "hello".toByteArray(), aad)
        assertEquals("hello", String(DeviceStoreCrypto.open(key, sealed, aad)!!))
        assertNull(DeviceStoreCrypto.open(ByteArray(32) { 5 }, sealed, aad))
        assertNull(DeviceStoreCrypto.open(key, sealed, DeviceStoreCrypto.context("node", "acct_you")))
        assertNull(DeviceStoreCrypto.open(key, sealed.copyOf().also { it[it.size - 1] = (it.last() + 1).toByte() }, aad))
        assertNull(DeviceStoreCrypto.open(key, byteArrayOf(1, 2, 3), aad))
    }

    @Test
    fun savedMessagesComeBackOnlyUnderTheSameRelayShare() {
        val dir = Files.createTempDirectory("store").toFile()
        val secrets = FakeSecrets()
        val store = EncryptedDeviceStore(dir, secrets)
        val first = store.open(share(2), "node", "acct_me")!!
        first.save(snapshot())
        first.close()
        val saved = dir.listFiles()!!.single()
        assertFalse(String(saved.readBytes(), Charsets.ISO_8859_1).contains("secret plan"))

        val again = store.open(share(2), "node", "acct_me")!!
        val restored = again.load()!!
        assertEquals(listOf("m1", "m2"), restored.messages["dm_alice"]!!.map { it.id })
        assertEquals("secret plan", restored.messages["dm_alice"]!![0].content)
        assertEquals(mapOf("👍" to listOf("acct_bob")), restored.messages["dm_alice"]!![0].reactions)
        assertArrayEquals(ByteArray(32) { 3 }, restored.messages["dm_alice"]!![1].attachmentKey)
        assertEquals(4_000L, restored.messages["dm_alice"]!![1].voiceDurationMs)
        assertEquals("Weekend plans", restored.roomNames["forum_abc"])
        assertEquals("Alice", restored.displayNames["acct_alice"])
        again.close()

        // After a relay restart the share is new: the old file cannot be read and is deleted.
        val restarted = store.open(share(9), "node", "acct_me")!!
        assertNull(restarted.load())
        assertTrue(dir.listFiles()!!.isEmpty())
        dir.deleteRecursively()
    }

    @Test
    fun signingInDeletesOtherAccountsOfTheSameRelayButKeepsOtherRelays() {
        val dir = Files.createTempDirectory("store").toFile()
        val store = EncryptedDeviceStore(dir, FakeSecrets())
        store.open(share(2), "node", "acct_before_restart")!!.save(snapshot())
        store.open(share(3), "other-node", "acct_elsewhere")!!.save(snapshot())
        assertEquals(2, dir.listFiles()!!.size)
        // After a relay restart the same node hands out a new account.
        store.open(share(4), "node", "acct_after_restart")!!
        val names = dir.listFiles()!!.map { it.name }
        assertEquals(listOf(DeviceStoreCrypto.fileName("other-node", "acct_elsewhere")), names)
        dir.deleteRecursively()
    }

    @Test
    fun eraseAllDeletesFilesAndTheDeviceSecret() {
        val dir = Files.createTempDirectory("store").toFile()
        val secrets = FakeSecrets()
        val store = EncryptedDeviceStore(dir, secrets)
        store.open(share(2), "node", "acct_me")!!.save(snapshot())
        store.eraseAll()
        assertTrue(dir.listFiles()!!.isEmpty())
        assertEquals(1, secrets.destroyed)
        assertNull(secrets.secret)
        dir.deleteRecursively()
    }

    @Test
    fun snapshotDecodingIsStrictAndDropsExpiredMessages() {
        val encoded = DeviceStoreSnapshot.encode(snapshot())
        assertEquals(2, DeviceStoreSnapshot.decode(encoded)!!.messages["dm_alice"]!!.size)
        assertNull(DeviceStoreSnapshot.decode("not json".toByteArray()))
        assertNull(DeviceStoreSnapshot.decode("""{"version":2,"messages":{},"room_names":{},"display_names":{}}""".toByteArray()))
        assertNull(DeviceStoreSnapshot.decode("""{"version":1,"messages":{"../x":[]},"room_names":{},"display_names":{}}""".toByteArray()))
        val expiring = DeviceStoreSnapshot(
            mapOf("dm_a" to listOf(Message(id = "old", sender = "a", receiver = null, content = "x", timestampMs = 1_000L, selfDestructDurationSec = 5, readTimestampMs = 1_000L))),
            emptyMap(), emptyMap()
        )
        val decoded = DeviceStoreSnapshot.decode(DeviceStoreSnapshot.encode(expiring), nowMs = 1_000L + 10_000L)
        assertTrue(decoded!!.messages.isEmpty())
    }
}
