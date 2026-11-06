package com.abyssal.chat.data.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The device half of the store key. */
internal interface LocalSecretStore {
    /** The 32-byte local secret, created on first use; null if the device cannot provide one. */
    fun getOrCreate(): ByteArray?

    /** Deletes the secret and the key that protects it. */
    fun destroy()
}

/**
 * Keeps a random local secret on disk wrapped by a non-exportable AES key in
 * the Android Keystore (StrongBox when available). The file alone is useless
 * off this device, and deleting the Keystore key makes it unrecoverable.
 */
internal class KeystoreLocalSecretStore(context: Context) : LocalSecretStore {
    private val file = File(File(context.noBackupFilesDir, STORE_DIR).apply { mkdirs() }, "local.secret")

    override fun getOrCreate(): ByteArray? = runCatching {
        val key = keystoreKey()
        if (key != null && file.isFile) {
            unwrap(key, file.readBytes())?.let { return@runCatching it }
        }
        destroy()
        val created = keystoreKey(create = true) ?: return@runCatching null
        val secret = ByteArray(DeviceStoreCrypto.KEY_BYTES).also(SecureRandom()::nextBytes)
        writeAtomically(file, wrap(created, secret))
        secret
    }.getOrNull()

    override fun destroy() {
        overwriteAndDelete(file)
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun keystoreKey(create: Boolean = false): SecretKey? {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        fun generate(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .apply { if (strongBox && android.os.Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) }
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
                init(spec)
                generateKey()
            }
        }
        return runCatching { generate(strongBox = true) }.recoverCatching { generate(strongBox = false) }.getOrNull()
    }

    private fun wrap(key: SecretKey, secret: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.iv + cipher.doFinal(secret)
    }

    private fun unwrap(key: SecretKey, wrapped: ByteArray): ByteArray? = runCatching {
        require(wrapped.size == 12 + DeviceStoreCrypto.KEY_BYTES + 16)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, wrapped, 0, 12))
        cipher.doFinal(wrapped, 12, wrapped.size - 12)
    }.getOrNull()

    companion object {
        const val STORE_DIR = "device-store"
        private const val ALIAS = "abyssal-device-store-v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

/** Best effort: overwrite then delete. Flash may keep old blocks, which is why the data is encrypted. */
internal fun overwriteAndDelete(file: File) {
    if (!file.exists()) return
    runCatching { file.outputStream().use { it.write(ByteArray(file.length().toInt().coerceAtMost(1 shl 24))) } }
    file.delete()
}

internal fun writeAtomically(file: File, bytes: ByteArray) {
    val temp = File(file.parentFile, file.name + ".tmp")
    temp.outputStream().use {
        it.write(bytes)
        it.fd.sync()
    }
    if (!temp.renameTo(file)) {
        overwriteAndDelete(temp)
        error("Store unavailable")
    }
}
