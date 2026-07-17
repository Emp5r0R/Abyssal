package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.IIdentityService
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class NetworkIdentityService(
    private val client: OkHttpClient
) : IIdentityService {
    private var currentUser: User? = null

    override suspend fun enterAccount(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult {
        val unified = authenticate(endpoint, "/v1/account/enter", code, password)
        if (unified.accepted) return unified

        val login = authenticate(endpoint, "/v1/account/login", code, password)
        if (login.accepted) return login

        return authenticate(endpoint, "/v1/account/create", code, password)
    }

    override suspend fun createAccount(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = authenticate(
        endpoint = endpoint,
        path = "/v1/account/create",
        code = code,
        password = password
    )

    override suspend fun login(
        code: String,
        password: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = authenticate(
        endpoint = endpoint,
        path = "/v1/account/login",
        code = code,
        password = password
    )

    private suspend fun authenticate(
        endpoint: NodeEndpoint,
        path: String,
        code: String,
        password: String
    ): IdentityValidationResult = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("code", code)
            .put("password", password)
            .toString()
            .toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("${endpoint.apiBaseUrl}$path")
            .post(body)
            .build()

        try {
            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string().orEmpty()
                val json = responseBody.takeIf { it.isNotBlank() }?.let { JSONObject(it) }
                if (!response.isSuccessful) {
                    return@use IdentityValidationResult(
                        accepted = false,
                        error = "Wrong information."
                    )
                }

                IdentityValidationResult(
                    accepted = json?.optBoolean("accepted", false) == true,
                    created = json?.optBoolean("created", false) == true,
                    token = json?.optString("token")?.takeIf { it.isNotBlank() },
                    nodeId = json?.optString("node_id")?.takeIf { it.isNotBlank() },
                    username = json?.optString("username")?.takeIf { it.isNotBlank() },
                    maxRoomsPerUser = json
                        ?.optInt("max_rooms_per_user", DEFAULT_MAX_ROOMS_PER_USER)
                        ?.coerceIn(MIN_MAX_ROOMS_PER_USER, MAX_MAX_ROOMS_PER_USER)
                        ?: DEFAULT_MAX_ROOMS_PER_USER,
                    sessionInactivitySec = json
                        ?.optInt("session_inactivity_sec", DEFAULT_SESSION_INACTIVITY_SEC)
                        ?.coerceIn(MIN_SESSION_INACTIVITY_SEC, MAX_SESSION_INACTIVITY_SEC)
                        ?: DEFAULT_SESSION_INACTIVITY_SEC,
                    error = json?.optString("error")?.takeIf { it.isNotBlank() }
                )
            }
        } catch (e: IOException) {
            IdentityValidationResult(
                accepted = false,
                error = "Wrong information."
            )
        } catch (e: Exception) {
            IdentityValidationResult(
                accepted = false,
                error = "Wrong information."
            )
        }
    }

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

        runCatching {
            client.newCall(request).execute().use { response -> response.isSuccessful }
        }.getOrDefault(false)
    }

    override fun logout() {
        currentUser = null
    }

    private companion object {
        const val MIN_SESSION_INACTIVITY_SEC = 60
        const val MAX_SESSION_INACTIVITY_SEC = 24 * 60 * 60
        const val DEFAULT_SESSION_INACTIVITY_SEC = 15 * 60
        const val MIN_MAX_ROOMS_PER_USER = 1
        const val MAX_MAX_ROOMS_PER_USER = 100
        const val DEFAULT_MAX_ROOMS_PER_USER = 5
    }
}
