package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.IIdentityService
import java.io.IOException
import java.security.SecureRandom
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

    private val prefixes = listOf(
        "Silent", "Nebula", "Quantum", "Vortex", "Solar", "Cosmic", "Lunar",
        "Alpha", "Shadow", "Ghost", "Starlight", "Obsidian", "Frozen", "Electric"
    )

    private val suffixes = listOf(
        "Wolf", "Tiger", "Fox", "Eagle", "Falcon", "Leopard", "Spectre",
        "Titan", "Node", "Warp", "Core", "Entity", "Daemon", "Vector"
    )

    override suspend fun validateInviteCode(
        code: String,
        endpoint: NodeEndpoint
    ): IdentityValidationResult = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("code", code)
            .toString()
            .toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("${endpoint.apiBaseUrl}/v1/invite/validate")
            .post(body)
            .build()

        try {
            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string().orEmpty()
                val json = responseBody.takeIf { it.isNotBlank() }?.let { JSONObject(it) }
                if (!response.isSuccessful) {
                    return@use IdentityValidationResult(
                        accepted = false,
                        error = json?.optString("error")?.takeIf { it.isNotBlank() }
                            ?: "Node rejected the invite code."
                    )
                }

                IdentityValidationResult(
                    accepted = json?.optBoolean("accepted", false) == true,
                    token = json?.optString("token")?.takeIf { it.isNotBlank() },
                    nodeId = json?.optString("node_id")?.takeIf { it.isNotBlank() },
                    isAdmin = json?.optBoolean("admin", false) == true,
                    error = json?.optString("error")?.takeIf { it.isNotBlank() }
                )
            }
        } catch (e: IOException) {
            IdentityValidationResult(
                accepted = false,
                error = "Cannot reach ${endpoint.displayHost}."
            )
        } catch (e: Exception) {
            IdentityValidationResult(
                accepted = false,
                error = e.message ?: "Invite validation failed."
            )
        }
    }

    override suspend fun generateRandomIdentity(): User {
        val random = SecureRandom()
        val prefix = prefixes[random.nextInt(prefixes.size)]
        val suffix = suffixes[random.nextInt(suffixes.size)]
        val number = 100 + random.nextInt(900)

        val publicKey = ByteArray(32)
        random.nextBytes(publicKey)

        val user = User(
            username = "$prefix$suffix$number",
            publicKey = publicKey,
            isAdmin = false
        )
        currentUser = user
        return user
    }

    fun setCurrentUser(user: User) {
        currentUser = user
    }

    override fun getCurrentUser(): User? = currentUser

    override fun logout() {
        currentUser = null
    }
}
