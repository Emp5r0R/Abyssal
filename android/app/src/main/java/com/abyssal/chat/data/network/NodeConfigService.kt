package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.repository.INodeConfigService
import java.net.URI
import java.util.Locale

class InMemoryNodeConfigService : INodeConfigService {
    @Volatile
    private var activeSession: NodeSession? = null

    override fun normalizeNodeUrl(input: String): Result<NodeEndpoint> {
        return NodeUrlNormalizer.normalize(input)
    }

    override fun setActiveSession(session: NodeSession) {
        activeSession = session
    }

    override fun getActiveSession(): NodeSession? = activeSession

    override fun clear() {
        activeSession = null
    }
}

object NodeUrlNormalizer {
    private val supportedSchemes = setOf("http", "https", "ws", "wss")

    fun normalize(input: String): Result<NodeEndpoint> {
        val trimmed = input.trim()
        if (trimmed.isBlank()) {
            return Result.failure(IllegalArgumentException("Enter a node URL."))
        }

        val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"

        return runCatching {
            val uri = URI(withScheme)
            val scheme = uri.scheme?.lowercase(Locale.ROOT)
                ?: throw IllegalArgumentException("Node URL needs a scheme.")
            if (scheme !in supportedSchemes) {
                throw IllegalArgumentException("Use http, https, ws, or wss.")
            }
            val host = uri.host ?: throw IllegalArgumentException("Node URL needs a host.")
            val normalizedHost = host
                .lowercase(Locale.ROOT)
                .removePrefix("[")
                .removeSuffix("]")
            if (uri.userInfo != null || uri.rawQuery != null || uri.rawFragment != null) {
                throw IllegalArgumentException("Node URL is unavailable.")
            }
            if (!uri.rawPath.isNullOrBlank() && uri.rawPath != "/") {
                throw IllegalArgumentException("Node URL must not include a path.")
            }
            if (scheme in setOf("http", "ws") && !isLoopbackDevelopmentHost(normalizedHost)) {
                throw IllegalArgumentException("Remote nodes require HTTPS.")
            }
            val apiScheme = when (scheme) {
                "ws" -> "http"
                "wss" -> "https"
                else -> scheme
            }
            val wsScheme = when (scheme) {
                "http" -> "ws"
                "https" -> "wss"
                else -> scheme
            }

            val authority = buildString {
                if (':' in normalizedHost) append("[").append(normalizedHost).append("]")
                else append(normalizedHost)
                if (uri.port > 0) append(":").append(uri.port)
            }

            NodeEndpoint(
                inputUrl = trimmed,
                apiBaseUrl = "$apiScheme://$authority",
                wsBaseUrl = "$wsScheme://$authority",
                displayHost = authority
            )
        }
    }

    private fun isLoopbackDevelopmentHost(host: String): Boolean {
        return host.equals("localhost", ignoreCase = true) ||
            host == "127.0.0.1" ||
            host == "::1" ||
            host == "10.0.2.2"
    }
}
