package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.IIdentityService
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import java.util.concurrent.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import uniffi.abyssal_core.OpaqueClientStart
import uniffi.abyssal_core.opaqueClientFinishLogin
import uniffi.abyssal_core.opaqueClientFinishRegistration
import uniffi.abyssal_core.opaqueClientStart

class NetworkIdentityService(
    client: OkHttpClient,
    private val payloadCipher: InMemoryPayloadCipher,
    private val callFactory: Call.Factory = client
) : IIdentityService {
    private var currentUser: User? = null

    override suspend fun enterAccount(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = withContext(Dispatchers.IO) {
        if (
            code.trim().length !in 1..MAX_CODE_CHARS ||
            password.length !in MIN_PASSWORD_CHARS..MAX_PASSWORD_CHARS
        ) return@withContext rejected()
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        var opaque: OpaqueClientStart? = null
        var responseBytes: ByteArray? = null
        var context: ByteArray? = null
        try {
            opaque = opaqueClientStart(passwordBytes)
            val start = postJson(
                endpoint,
                "/v2/account/start",
                JSONObject()
                    .put("code", code)
                    .put("registration_request_b64", encode(opaque.registrationRequest))
                    .put("credential_request_b64", encode(opaque.credentialRequest))
            ) ?: return@withContext rejected()
            if (!start.optBoolean("accepted", false)) return@withContext rejected()

            val handshakeId = start.optString("handshake_id")
                .takeIf { HANDSHAKE_ID_REGEX.matches(it) }
                ?: return@withContext rejected()
            val mode = start.optString("mode")
            val nodeId = start.optString("node_id")
                .takeIf { isBoundedAscii(it, MAX_NODE_ID_CHARS) }
                ?: return@withContext rejected()
            responseBytes = decode(start.optString("response_b64")).also {
                require(it.isNotEmpty() && it.size <= MAX_OPAQUE_RESPONSE_BYTES)
            }
            context = identityContext(nodeId, code)

            val finishBody = JSONObject().put("handshake_id", handshakeId)
            when (mode) {
                "registration" -> {
                    val result = opaqueClientFinishRegistration(
                        passwordBytes,
                        opaque.registrationState,
                        responseBytes
                    )
                    try {
                        val identity = payloadCipher.createIdentity(result.exportKey, context)
                        try {
                            finishBody
                                .put("registration_upload_b64", encode(result.registrationUpload))
                                .put("identity_public_b64", encode(identity.publicKey))
                                .put("identity_prekey_id", identity.prekeyId)
                                .put("identity_envelope_b64", encode(identity.envelope))
                        } finally {
                            identity.publicKey.fill(0)
                            identity.envelope.fill(0)
                        }
                    } finally {
                        result.registrationUpload.fill(0)
                        result.exportKey.fill(0)
                    }
                }
                "login" -> {
                    val serverPrekeyId = start.optString("identity_prekey_id")
                        .takeIf { it.matches(PREKEY_ID_REGEX) }
                        ?: return@withContext rejectedAndClear()
                    var identityPublic: ByteArray? = null
                    var identityEnvelope: ByteArray? = null
                    try {
                        val identityPublicBytes = decode(start.optString("identity_public_b64"))
                        if (identityPublicBytes.size != IDENTITY_PUBLIC_KEY_BYTES) {
                            return@withContext rejectedAndClear()
                        }
                        identityPublic = identityPublicBytes
                        val identityEnvelopeBytes = decode(start.optString("identity_envelope_b64"))
                        if (identityEnvelopeBytes.isEmpty() || identityEnvelopeBytes.size > MAX_IDENTITY_ENVELOPE_BYTES) {
                            return@withContext rejectedAndClear()
                        }
                        identityEnvelope = identityEnvelopeBytes
                        val result = opaqueClientFinishLogin(
                            passwordBytes,
                            opaque.loginState,
                            responseBytes
                        )
                        try {
                            payloadCipher.recoverIdentity(
                                result.exportKey,
                                context,
                                identityEnvelopeBytes,
                                identityPublicBytes
                            )
                            if (payloadCipher.prekeyId() != serverPrekeyId) {
                                return@withContext rejectedAndClear()
                            }
                            finishBody.put(
                                "credential_finalization_b64",
                                encode(result.credentialFinalization)
                            )
                        } finally {
                            result.credentialFinalization.fill(0)
                            result.exportKey.fill(0)
                        }
                    } finally {
                        identityPublic?.fill(0)
                        identityEnvelope?.fill(0)
                    }
                }
                else -> return@withContext rejected()
            }

            val finish = postJson(endpoint, "/v2/account/finish", finishBody)
                ?: return@withContext rejectedAndClear()
            if (!finish.optBoolean("accepted", false)) return@withContext rejectedAndClear()
            val publicKey = payloadCipher.publicKey()
            val serverPublicKey = decode(finish.optString("identity_public_b64"))
            if (!publicKey.contentEquals(serverPublicKey)) {
                publicKey.fill(0)
                serverPublicKey.fill(0)
                return@withContext rejectedAndClear()
            }
            serverPublicKey.fill(0)
            try {
                parseAccepted(finish, publicKey)
            } catch (_: Exception) {
                publicKey.fill(0)
                throw IllegalArgumentException("Identity unavailable")
            }
        } catch (error: CancellationException) {
            payloadCipher.clear()
            throw error
        } catch (_: Exception) {
            rejectedAndClear()
        } finally {
            passwordBytes.fill(0)
            responseBytes?.fill(0)
            context?.fill(0)
            opaque?.registrationState?.fill(0)
            opaque?.registrationRequest?.fill(0)
            opaque?.loginState?.fill(0)
            opaque?.credentialRequest?.fill(0)
        }
    }

    override suspend fun createAccount(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = enterAccount(code, password, endpoint)

    override suspend fun login(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = enterAccount(code, password, endpoint)

    override fun setCurrentUser(user: User) {
        currentUser = user
    }

    override fun getCurrentUser(): User? = currentUser

    override suspend fun revokeSession(session: NodeSession): Boolean = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/account/logout")
            .header("Authorization", "Bearer ${session.token}")
            .post(ByteArray(0).toRequestBody(null))
            .build()
        try {
            awaitHttpResponse(callFactory.newCall(request)) { response -> response.isSuccessful }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    override fun logout() {
        currentUser = null
    }

    private suspend fun postJson(endpoint: NodeEndpoint, path: String, json: JSONObject): JSONObject? {
        val requestBytes = json.toString().toByteArray(StandardCharsets.UTF_8)
        val request = Request.Builder()
            .url("${endpoint.apiBaseUrl}$path")
            .post(requestBytes.toRequestBody(JSON_MEDIA_TYPE))
            .build()
        return try {
            awaitHttpResponse(callFactory.newCall(request)) { response ->
                if (!response.isSuccessful) return@awaitHttpResponse null
                val body = response.body ?: return@awaitHttpResponse null
                if (body.contentLength() > MAX_ACCOUNT_RESPONSE_BYTES) return@awaitHttpResponse null
                val raw = BoundedInputReader.read(body.byteStream(), MAX_ACCOUNT_RESPONSE_BYTES)
                    ?: return@awaitHttpResponse null
                try {
                    raw.takeIf { it.isNotEmpty() }?.let {
                        JSONObject(String(it, StandardCharsets.UTF_8))
                    }
                } finally {
                    raw.fill(0)
                }
            }
        } finally {
            requestBytes.fill(0)
        }
    }

    private fun parseAccepted(json: JSONObject, publicKey: ByteArray): IdentityValidationResult {
        val token = json.optString("token").takeIf { isBoundedAscii(it, MAX_TOKEN_CHARS) }
            ?: throw IllegalArgumentException("Identity unavailable")
        val nodeId = json.optString("node_id").takeIf { isBoundedAscii(it, MAX_NODE_ID_CHARS) }
            ?: throw IllegalArgumentException("Identity unavailable")
        val username = json.optString("username").takeIf { isBoundedAscii(it, MAX_USERNAME_CHARS) }
            ?: throw IllegalArgumentException("Identity unavailable")
        return IdentityValidationResult(
            accepted = true,
            created = json.optBoolean("created", false),
            token = token,
            nodeId = nodeId,
            username = username,
            maxRoomsPerUser = json
                .optInt("max_rooms_per_user", DEFAULT_MAX_ROOMS_PER_USER)
                .coerceIn(MIN_MAX_ROOMS_PER_USER, MAX_MAX_ROOMS_PER_USER),
            sessionInactivitySec = json
                .optInt("session_inactivity_sec", DEFAULT_SESSION_INACTIVITY_SEC)
                .coerceIn(MIN_SESSION_INACTIVITY_SEC, MAX_SESSION_INACTIVITY_SEC),
            publicKey = publicKey,
            prekeyId = json.optString("identity_prekey_id")
                .takeIf { it.matches(PREKEY_ID_REGEX) }
                ?: throw IllegalArgumentException("Identity unavailable")
        )
    }

    private fun rejected(): IdentityValidationResult =
        IdentityValidationResult(accepted = false, error = "Wrong information.")

    private fun rejectedAndClear(): IdentityValidationResult {
        payloadCipher.clear()
        return rejected()
    }

    private fun identityContext(nodeId: String, code: String): ByteArray {
        val node = nodeId.trim()
        val credential = code.trim().uppercase(Locale.ROOT)
        require(node.isNotEmpty() && node.length <= 128)
        require(credential.isNotEmpty() && credential.length <= 128)
        return "ABYSSAL_IDENTITY_V2:$node:$credential".toByteArray(StandardCharsets.UTF_8)
    }

    private companion object {
        const val MIN_SESSION_INACTIVITY_SEC = 60
        const val MAX_SESSION_INACTIVITY_SEC = 24 * 60 * 60
        const val DEFAULT_SESSION_INACTIVITY_SEC = 15 * 60
        const val MIN_MAX_ROOMS_PER_USER = 1
        const val MAX_MAX_ROOMS_PER_USER = 100
        const val DEFAULT_MAX_ROOMS_PER_USER = 5
        const val MIN_PASSWORD_CHARS = 8
        const val MAX_PASSWORD_CHARS = 512
        const val MAX_CODE_CHARS = 128
        const val MAX_NODE_ID_CHARS = 128
        const val MAX_USERNAME_CHARS = 80
        const val MAX_TOKEN_CHARS = 128
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        const val MAX_IDENTITY_ENVELOPE_BYTES = 512 * 1024
        const val MAX_OPAQUE_RESPONSE_BYTES = 64 * 1024
        const val MAX_ACCOUNT_RESPONSE_BYTES = 1 * 1024 * 1024L
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        val HANDSHAKE_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,128}$")
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        fun isBoundedAscii(value: String, maxLength: Int): Boolean =
            value.length in 1..maxLength && value.all { it.code in 0x20..0x7e }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray {
            require(value.isNotBlank())
            return Base64.getUrlDecoder().decode(value)
        }
    }
}
