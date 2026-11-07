package com.abyssal.chat.data.network

import com.abyssal.chat.data.network.v11.AccountBootstrapClient
import com.abyssal.chat.data.network.v11.BootstrapSignIn
import com.abyssal.chat.data.network.v11.BootstrapSignInInput
import com.abyssal.chat.data.network.v11.ControlExchanges
import com.abyssal.chat.data.network.v11.SealedRecordHttp
import com.abyssal.chat.data.network.v11.UniffiControlExchanges
import com.abyssal.chat.data.network.v11.asBootstrapIdentity
import com.abyssal.chat.data.network.v11.logoutV11
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.TransportKeys
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.IIdentityService
import java.util.UUID
import java.util.concurrent.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.OkHttpClient

/**
 * Account entry and logout over protocol v11: the sealed bootstrap for
 * sign-in and registration, and a sealed control record for logout. Nothing
 * readable, and no bearer token, ever leaves the device.
 */
class NetworkIdentityService internal constructor(
    private val payloadCipher: InMemoryPayloadCipher,
    private val callFactory: Call.Factory,
    private val bootstrap: AccountBootstrapClient,
    private val controlExchanges: ControlExchanges
) : IIdentityService {
    constructor(
        client: OkHttpClient,
        payloadCipher: InMemoryPayloadCipher,
        callFactory: Call.Factory = client
    ) : this(
        payloadCipher,
        callFactory,
        AccountBootstrapClient(post = { url, record ->
            SealedRecordHttp.post(callFactory, url, record, SealedRecordHttp.MAX_BOOTSTRAP_REPLY_BYTES)
        }),
        UniffiControlExchanges
    )

    private var currentUser: User? = null

    override suspend fun enterAccount(
        capability: ByteArray,
        accountContext: ByteArray,
        expectedNodeId: String,
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        password: ByteArray,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = withContext(Dispatchers.IO) {
        var signedIn: BootstrapSignIn? = null
        var handedOver = false
        try {
            if (
                capability.size != CAPABILITY_BYTES ||
                accountContext.size != ACCOUNT_CONTEXT_BYTES ||
                nodePublicKey.size != NODE_KEY_BYTES ||
                bootstrapPublicKey.size != NODE_KEY_BYTES ||
                password.size !in MIN_PASSWORD_CHARS..MAX_PASSWORD_CHARS
            ) return@withContext rejected()
            val result = bootstrap.signIn(
                BootstrapSignInInput(
                    apiBaseUrl = endpoint.apiBaseUrl,
                    nodeId = expectedNodeId,
                    nodePublicKey = nodePublicKey,
                    bootstrapPublicKey = bootstrapPublicKey,
                    capability = capability,
                    accountContext = accountContext,
                    password = password,
                    identity = payloadCipher.asBootstrapIdentity()
                )
            )
            signedIn = result
            val publicKey = payloadCipher.publicKey()
            if (!acceptable(result, publicKey)) {
                publicKey.fill(0)
                // The relay authenticated this session but the client refuses it:
                // log it out rather than leave it to expire.
                revoke(endpoint.apiBaseUrl, result.keys)
                return@withContext rejectedAndClear()
            }
            handedOver = true
            IdentityValidationResult(
                accepted = true,
                created = result.created,
                // A local identity for this session only; v11 authenticates with the keys.
                token = UUID.randomUUID().toString(),
                nodeId = expectedNodeId,
                username = result.username,
                maxRoomsPerUser = result.maxRoomsPerUser,
                sessionInactivitySec = result.sessionInactivitySec,
                publicKey = publicKey,
                prekeyId = result.identityPrekeyId,
                deviceStorageShare = result.deviceStorageShare,
                transport = result.keys
            )
        } catch (error: CancellationException) {
            payloadCipher.clear()
            throw error
        } catch (_: Exception) {
            rejectedAndClear()
        } finally {
            password.fill(0)
            capability.fill(0)
            accountContext.fill(0)
            signedIn?.identityPublic?.fill(0)
            if (!handedOver) {
                signedIn?.deviceStorageShare?.fill(0)
                signedIn?.keys?.destroy()
            }
        }
    }

    private fun acceptable(result: BootstrapSignIn, publicKey: ByteArray): Boolean =
        result.consistent &&
            USERNAME_REGEX.matches(result.username) &&
            result.maxRoomsPerUser in MIN_MAX_ROOMS_PER_USER..MAX_MAX_ROOMS_PER_USER &&
            result.sessionInactivitySec in MIN_SESSION_INACTIVITY_SEC..MAX_SESSION_INACTIVITY_SEC &&
            result.identityPublic.size == IDENTITY_PUBLIC_KEY_BYTES &&
            result.identityPublic.contentEquals(publicKey) &&
            PREKEY_ID_REGEX.matches(result.identityPrekeyId) &&
            result.identityPrekeyId == payloadCipher.prekeyId() &&
            (result.deviceStorageShare == null || result.deviceStorageShare.size == DEVICE_STORAGE_SHARE_BYTES) &&
            result.keys.sessionId.size == NODE_KEY_BYTES &&
            result.keys.transportRoot.size == NODE_KEY_BYTES

    override fun setCurrentUser(user: User) {
        currentUser = user
    }

    override fun getCurrentUser(): User? = currentUser

    override suspend fun revokeSession(session: NodeSession): Boolean = withContext(Dispatchers.IO) {
        try {
            logoutV11(callFactory, session.endpoint.apiBaseUrl, session.transport, controlExchanges)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        } finally {
            session.transport.destroy()
        }
    }

    /** Bounded best-effort logout of keys that will not be used, then wipes them. */
    private suspend fun revoke(apiBaseUrl: String, keys: TransportKeys) {
        withContext(NonCancellable) {
            withTimeoutOrNull(REVOKE_TIMEOUT_MS) {
                runCatching { logoutV11(callFactory, apiBaseUrl, keys, controlExchanges) }
            }
        }
        keys.destroy()
    }

    override fun logout() {
        currentUser = null
    }

    private fun rejected(): IdentityValidationResult =
        IdentityValidationResult(accepted = false, error = "Wrong information.")

    private fun rejectedAndClear(): IdentityValidationResult {
        payloadCipher.clear()
        return rejected()
    }

    private companion object {
        const val MIN_PASSWORD_CHARS = 8
        const val MAX_PASSWORD_CHARS = 512
        const val CAPABILITY_BYTES = 32
        const val ACCOUNT_CONTEXT_BYTES = 32
        const val NODE_KEY_BYTES = 32
        const val REVOKE_TIMEOUT_MS = 3_000L
    }
}

private const val MIN_SESSION_INACTIVITY_SEC = 60
private const val MAX_SESSION_INACTIVITY_SEC = 24 * 60 * 60
private const val MIN_MAX_ROOMS_PER_USER = 1
private const val MAX_MAX_ROOMS_PER_USER = 100
private const val IDENTITY_PUBLIC_KEY_BYTES = 608
private const val DEVICE_STORAGE_SHARE_BYTES = 32
private val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
private val USERNAME_REGEX = Regex("^[A-Za-z0-9_-]{1,80}$")
