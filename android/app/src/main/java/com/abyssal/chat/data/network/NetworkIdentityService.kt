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

internal data class ValidatedOpaqueStartResponse(
    val handshakeId: String,
    val mode: String,
    val nodeId: String,
    val responseB64: String,
    val challengeB64: String?,
    val identityPublicB64: String?,
    val identityPrekeyId: String?,
    val identityEnvelopeB64: String?
)

internal data class ValidatedAccountResponse(
    val created: Boolean,
    val token: String,
    val nodeId: String,
    val username: String,
    val maxRoomsPerUser: Int,
    val sessionInactivitySec: Int,
    val identityPublicB64: String,
    val identityPrekeyId: String
)

internal fun validateOpaqueStartResponse(json: JSONObject): ValidatedOpaqueStartResponse? {
    if (!json.hasOnlyKeys(OPAQUE_START_RESPONSE_KEYS)) return null
    if (json.strictBoolean("accepted") != true || !json.isNullish("error")) return null
    val mode = json.strictString("mode")?.takeIf { it == "registration" || it == "login" }
        ?: return null
    val handshakeId = json.strictString("handshake_id")?.takeIf(UUID_V4_REGEX::matches)
        ?: return null
    val nodeId = json.strictString("node_id")?.takeIf(NODE_ID_REGEX::matches) ?: return null
    val responseB64 = json.strictString("response_b64")
        ?.takeIf { isCanonicalBase64Url(it, 1, MAX_OPAQUE_RESPONSE_BYTES) }
        ?: return null
    val challengeB64 = json.strictString("challenge_b64")

    var identityPublicB64: String? = null
    var identityPrekeyId: String? = null
    var identityEnvelopeB64: String? = null
    if (mode == "registration") {
        if (
            !json.isNullish("identity_public_b64") ||
            !json.isNullish("identity_prekey_id") ||
            !json.isNullish("identity_envelope_b64") ||
            challengeB64 == null ||
            !isCanonicalBase64Url(challengeB64, REGISTRATION_CHALLENGE_BYTES, REGISTRATION_CHALLENGE_BYTES)
        ) return null
    } else {
        if (challengeB64 != null) return null
        identityPublicB64 = json.strictString("identity_public_b64")
        identityPrekeyId = json.strictString("identity_prekey_id")
        identityEnvelopeB64 = json.strictString("identity_envelope_b64")
    }
    if (mode == "login" && (
        identityPublicB64 == null ||
        !isCanonicalBase64Url(identityPublicB64, IDENTITY_PUBLIC_KEY_BYTES, IDENTITY_PUBLIC_KEY_BYTES) ||
        identityPrekeyId?.matches(PREKEY_ID_REGEX) != true ||
        identityEnvelopeB64 == null ||
        !isCanonicalBase64Url(identityEnvelopeB64, 1, MAX_IDENTITY_ENVELOPE_BYTES)
    )) return null
    return ValidatedOpaqueStartResponse(
        handshakeId,
        mode,
        nodeId,
        responseB64,
        challengeB64,
        identityPublicB64,
        identityPrekeyId,
        identityEnvelopeB64
    )
}

internal fun validateAcceptedAccountResponse(
    json: JSONObject,
    expectedNodeId: String,
    expectedCreated: Boolean,
    expectedPrekeyId: String
): ValidatedAccountResponse? {
    if (!json.hasOnlyKeys(ACCOUNT_RESPONSE_KEYS)) return null
    if (json.strictBoolean("accepted") != true || !json.isNullish("error")) return null
    val created = json.strictBoolean("created")?.takeIf { it == expectedCreated } ?: return null
    val token = json.strictString("token")?.takeIf(UUID_V4_REGEX::matches) ?: return null
    val nodeId = json.strictString("node_id")
        ?.takeIf { NODE_ID_REGEX.matches(it) && it == expectedNodeId }
        ?: return null
    val username = json.strictString("username")?.takeIf(USERNAME_REGEX::matches) ?: return null
    val maxRooms = json.strictInt("max_rooms_per_user")
        ?.takeIf { it in MIN_MAX_ROOMS_PER_USER..MAX_MAX_ROOMS_PER_USER }
        ?: return null
    val inactivity = json.strictInt("session_inactivity_sec")
        ?.takeIf { it in MIN_SESSION_INACTIVITY_SEC..MAX_SESSION_INACTIVITY_SEC }
        ?: return null
    val publicKeyB64 = json.strictString("identity_public_b64")
        ?.takeIf { isCanonicalBase64Url(it, IDENTITY_PUBLIC_KEY_BYTES, IDENTITY_PUBLIC_KEY_BYTES) }
        ?: return null
    val prekeyId = json.strictString("identity_prekey_id")
        ?.takeIf { PREKEY_ID_REGEX.matches(it) && it == expectedPrekeyId }
        ?: return null
    json.strictString("identity_envelope_b64")
        ?.takeIf { isCanonicalBase64Url(it, 1, MAX_IDENTITY_ENVELOPE_BYTES) }
        ?: return null
    return ValidatedAccountResponse(
        created,
        token,
        nodeId,
        username,
        maxRooms,
        inactivity,
        publicKeyB64,
        prekeyId
    )
}

class NetworkIdentityService(
    client: OkHttpClient,
    private val payloadCipher: InMemoryPayloadCipher,
    private val callFactory: Call.Factory = client
) : IIdentityService {
    private var currentUser: User? = null

    override suspend fun enterAccount(
        code: String,
        password: ByteArray,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = withContext(Dispatchers.IO) {
        var opaque: OpaqueClientStart? = null
        var responseBytes: ByteArray? = null
        var context: ByteArray? = null
        try {
            if (
                code.trim().length !in 1..MAX_CODE_CHARS ||
                password.size !in MIN_PASSWORD_CHARS..MAX_PASSWORD_CHARS
            ) return@withContext rejected()
            opaque = opaqueClientStart(password)
            val start = postJson(
                endpoint,
                "/v2/account/start",
                JSONObject()
                    .put("code", code)
                    .put("registration_request_b64", encode(opaque.registrationRequest))
                    .put("credential_request_b64", encode(opaque.credentialRequest))
            ) ?: return@withContext rejected()
            val validatedStart = validateOpaqueStartResponse(start) ?: return@withContext rejected()
            val handshakeId = validatedStart.handshakeId
            val mode = validatedStart.mode
            val nodeId = validatedStart.nodeId
            responseBytes = decodeIdentityBase64(validatedStart.responseB64)
            context = identityContext(nodeId, code)

            val finishBody = JSONObject().put("handshake_id", handshakeId)
            when (mode) {
                "registration" -> {
                    val result = opaqueClientFinishRegistration(
                        password,
                        opaque.registrationState,
                        responseBytes
                    )
                    try {
                        val identity = payloadCipher.createIdentity(result.exportKey, context)
                        var challenge = ByteArray(0)
                        var identityProof = ByteArray(0)
                        try {
                            challenge = decodeIdentityBase64(
                                validatedStart.challengeB64 ?: return@withContext rejectedAndClear()
                            )
                            identityProof = payloadCipher.signRegistrationIdentityProof(
                                nodeId = nodeId,
                                handshakeId = handshakeId,
                                challenge = challenge,
                                registrationUpload = result.registrationUpload,
                                identityPublic = identity.publicKey,
                                prekeyId = identity.prekeyId,
                                identityEnvelope = identity.envelope
                            )
                            finishBody
                                .put("registration_upload_b64", encode(result.registrationUpload))
                                .put("identity_public_b64", encode(identity.publicKey))
                                .put("identity_prekey_id", identity.prekeyId)
                                .put("identity_envelope_b64", encode(identity.envelope))
                                .put("identity_proof_b64", encode(identityProof))
                        } finally {
                            challenge.fill(0)
                            identityProof.fill(0)
                            identity.publicKey.fill(0)
                            identity.envelope.fill(0)
                        }
                    } finally {
                        result.registrationUpload.fill(0)
                        result.exportKey.fill(0)
                    }
                }
                "login" -> {
                    val serverPrekeyId = validatedStart.identityPrekeyId
                        ?: return@withContext rejectedAndClear()
                    var identityPublic: ByteArray? = null
                    var identityEnvelope: ByteArray? = null
                    try {
                        val identityPublicBytes = decodeIdentityBase64(
                            validatedStart.identityPublicB64 ?: return@withContext rejectedAndClear()
                        )
                        identityPublic = identityPublicBytes
                        val identityEnvelopeBytes = decodeIdentityBase64(
                            validatedStart.identityEnvelopeB64 ?: return@withContext rejectedAndClear()
                        )
                        identityEnvelope = identityEnvelopeBytes
                        val result = opaqueClientFinishLogin(
                            password,
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
            val expectedPrekeyId = payloadCipher.prekeyId()
            val validatedFinish = validateAcceptedAccountResponse(
                json = finish,
                expectedNodeId = nodeId,
                expectedCreated = mode == "registration",
                expectedPrekeyId = expectedPrekeyId
            ) ?: return@withContext rejectedAndClear()
            val publicKey = payloadCipher.publicKey()
            val serverPublicKey = decodeIdentityBase64(validatedFinish.identityPublicB64)
            if (!publicKey.contentEquals(serverPublicKey)) {
                publicKey.fill(0)
                serverPublicKey.fill(0)
                return@withContext rejectedAndClear()
            }
            serverPublicKey.fill(0)
            try {
                parseAccepted(validatedFinish, publicKey)
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
            password.fill(0)
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
        password: ByteArray,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = enterAccount(code, password, endpoint)

    override suspend fun login(
        code: String,
        password: ByteArray,
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

    private fun parseAccepted(
        response: ValidatedAccountResponse,
        publicKey: ByteArray
    ): IdentityValidationResult {
        return IdentityValidationResult(
            accepted = true,
            created = response.created,
            token = response.token,
            nodeId = response.nodeId,
            username = response.username,
            maxRoomsPerUser = response.maxRoomsPerUser,
            sessionInactivitySec = response.sessionInactivitySec,
            publicKey = publicKey,
            prekeyId = response.identityPrekeyId
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
        // The identity context is shared by Android and web clients.  The
        // sealed envelope's protocol domain is versioned natively; retaining
        // this account context keeps cross-client login/recovery compatible.
        return "ABYSSAL_IDENTITY_V2:$node:$credential".toByteArray(StandardCharsets.UTF_8)
    }

    private companion object {
        const val MIN_PASSWORD_CHARS = 8
        const val MAX_PASSWORD_CHARS = 512
        const val MAX_CODE_CHARS = 128
        const val MAX_ACCOUNT_RESPONSE_BYTES = 1 * 1024 * 1024L
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

private const val MIN_SESSION_INACTIVITY_SEC = 60
private const val MAX_SESSION_INACTIVITY_SEC = 24 * 60 * 60
private const val MIN_MAX_ROOMS_PER_USER = 1
private const val MAX_MAX_ROOMS_PER_USER = 100
private const val IDENTITY_PUBLIC_KEY_BYTES = 608
private const val REGISTRATION_CHALLENGE_BYTES = 32
private const val MAX_IDENTITY_ENVELOPE_BYTES = 512 * 1024
private const val MAX_OPAQUE_RESPONSE_BYTES = 64 * 1024
private val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
private val UUID_V4_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
private val NODE_ID_REGEX = Regex("^[A-Za-z0-9._:-]{1,128}$")
private val USERNAME_REGEX = Regex("^[A-Za-z0-9_-]{1,80}$")
private val BASE64_URL_REGEX = Regex("^[A-Za-z0-9_-]+$")
private val OPAQUE_START_RESPONSE_KEYS = setOf(
    "accepted", "mode", "handshake_id", "response_b64", "challenge_b64", "node_id",
    "identity_public_b64", "identity_prekey_id", "identity_envelope_b64", "error"
)
private val ACCOUNT_RESPONSE_KEYS = setOf(
    "accepted", "created", "token", "node_id", "username", "max_rooms_per_user",
    "session_inactivity_sec", "identity_public_b64", "identity_prekey_id",
    "identity_envelope_b64", "error"
)

private fun JSONObject.hasOnlyKeys(allowed: Set<String>): Boolean =
    keys().asSequence().all { it in allowed }

private fun JSONObject.isNullish(name: String): Boolean = !has(name) || isNull(name)

private fun JSONObject.strictBoolean(name: String): Boolean? =
    if (!has(name) || isNull(name)) null else opt(name) as? Boolean

private fun JSONObject.strictString(name: String): String? =
    if (!has(name) || isNull(name)) null else opt(name) as? String

private fun JSONObject.strictInt(name: String): Int? {
    if (!has(name) || isNull(name)) return null
    return when (val value = opt(name)) {
        is Int -> value
        is Long -> value.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
        else -> null
    }
}

private fun isCanonicalBase64Url(value: String, minBytes: Int, maxBytes: Int): Boolean {
    if (!BASE64_URL_REGEX.matches(value) || value.length > ((maxBytes + 2) / 3) * 4) return false
    val decoded = runCatching { decodeIdentityBase64(value) }.getOrNull() ?: return false
    return try {
        decoded.size in minBytes..maxBytes &&
            Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value
    } finally {
        decoded.fill(0)
    }
}

private fun decodeIdentityBase64(value: String): ByteArray {
    require(value.isNotBlank())
    return Base64.getUrlDecoder().decode(value)
}
