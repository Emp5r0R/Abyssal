package com.abyssal.chat.data.storage

import com.abyssal.chat.domain.model.DeviceStoreSnapshot
import java.io.File

/**
 * The on-device store used when the relay allows device storage. Each relay
 * account has one sealed file; its key exists only in memory while signed in.
 */
class EncryptedDeviceStore internal constructor(private val directory: File, private val secrets: LocalSecretStore) {
    /** Opens the store for an account, or null if the device cannot hold a local secret. */
    internal fun open(relayShare: ByteArray, nodeId: String, username: String): Session? {
        val local = secrets.getOrCreate() ?: return null
        return try {
            Session(
                key = DeviceStoreCrypto.deriveKey(local, relayShare, nodeId, username),
                file = File(directory.apply { mkdirs() }, DeviceStoreCrypto.fileName(nodeId, username)),
                aad = DeviceStoreCrypto.context(nodeId, username)
            )
        } finally {
            local.fill(0)
        }
    }

    /** Deletes every saved file and the device key, so nothing saved before can be decrypted again. */
    internal fun eraseAll() {
        directory.listFiles()?.forEach(::overwriteAndDelete)
        secrets.destroy()
    }

    inner class Session internal constructor(private val key: ByteArray, private val file: File, private val aad: ByteArray) {
        @Volatile private var closed = false

        /**
         * The saved snapshot, or null when there is none. A file that does not
         * open under this key was saved under a share the relay no longer has
         * (it restarted or was wiped), so it is deleted.
         */
        @Synchronized
        fun load(): DeviceStoreSnapshot? {
            if (closed || !file.isFile) return null
            val plain = DeviceStoreCrypto.open(key, file.readBytes(), aad)
            if (plain == null) {
                overwriteAndDelete(file)
                return null
            }
            return try {
                DeviceStoreSnapshot.decode(plain) ?: run { overwriteAndDelete(file); null }
            } finally {
                plain.fill(0)
            }
        }

        @Synchronized
        fun save(snapshot: DeviceStoreSnapshot) {
            if (closed) return
            val plain = DeviceStoreSnapshot.encode(snapshot)
            try {
                writeAtomically(file, DeviceStoreCrypto.seal(key, plain, aad))
            } finally {
                plain.fill(0)
            }
        }

        /** Deletes this account's file. */
        @Synchronized
        fun erase() = overwriteAndDelete(file)

        /** Wipes the key from memory; the file stays for the next sign-in. */
        @Synchronized
        fun close() {
            closed = true
            key.fill(0)
        }
    }
}
