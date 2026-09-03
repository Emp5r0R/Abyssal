package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.VerifiedInvite
import com.abyssal.chat.domain.repository.IInviteBootstrapService
import com.abyssal.chat.domain.repository.INodeConfigService
import java.util.concurrent.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.CacheControl
import okhttp3.OkHttpClient
import okhttp3.Request
import uniffi.abyssal_core.parseInviteCapsule
import uniffi.abyssal_core.verifyInviteNodeDescriptor

class InviteBootstrapService(
    client: OkHttpClient,
    private val nodeConfigService: INodeConfigService,
    private val allowDevelopmentLoopback: Boolean,
    private val callFactory: Call.Factory = client
) : IInviteBootstrapService {
    override suspend fun verify(invite: String): Result<VerifiedInvite> = withContext(Dispatchers.IO) {
        var nodePublicKey = ByteArray(0)
        var capability = ByteArray(0)
        var accountContext = ByteArray(0)
        try {
            val parsed = parseInviteCapsule(
                inviteText = invite,
                nowUnixSeconds = (System.currentTimeMillis() / 1_000L).toULong(),
                allowDevelopmentLoopback = allowDevelopmentLoopback
            )
            nodePublicKey = parsed.nodePublicKey
            capability = parsed.capability
            accountContext = parsed.accountContext
            require(nodePublicKey.size == NODE_PUBLIC_KEY_BYTES)
            require(capability.size == CAPABILITY_BYTES)
            require(accountContext.size == ACCOUNT_CONTEXT_BYTES)
            val endpoint = nodeConfigService.normalizeNodeUrl(parsed.nodeUrl).getOrThrow()
            require(endpoint.apiBaseUrl == parsed.nodeUrl)
            val descriptor = fetchDescriptor(endpoint.apiBaseUrl)
                ?: throw IllegalArgumentException("Unable to verify node")
            try {
                verifyInviteNodeDescriptor(descriptor, nodePublicKey, endpoint.apiBaseUrl)
            } finally {
                descriptor.fill(0)
            }
            val result = VerifiedInvite(
                nodeId = parsed.nodeId,
                nodePublicKey = nodePublicKey.copyOf(),
                endpoint = endpoint,
                capability = capability.copyOf(),
                accountContext = accountContext.copyOf()
            )
            Result.success(result)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            Result.failure(IllegalArgumentException(error.message ?: "Invalid invite"))
        } finally {
            nodePublicKey.fill(0)
            capability.fill(0)
            accountContext.fill(0)
        }
    }

    private suspend fun fetchDescriptor(apiBaseUrl: String): ByteArray? {
        val request = Request.Builder()
            .url("$apiBaseUrl/v1/node")
            .cacheControl(CacheControl.FORCE_NETWORK)
            .header("Accept", NODE_DESCRIPTOR_MEDIA_TYPE)
            .get()
            .build()
        return awaitHttpResponse(callFactory.newCall(request)) { response ->
            if (response.request.url != request.url) return@awaitHttpResponse null
            if (!response.isSuccessful) return@awaitHttpResponse null
            val body = response.body ?: return@awaitHttpResponse null
            val contentType = body.contentType()
            if (contentType?.type != "application" || contentType.subtype != "cbor") {
                return@awaitHttpResponse null
            }
            if (body.contentLength() > MAX_NODE_DESCRIPTOR_BYTES) return@awaitHttpResponse null
            BoundedInputReader.read(body.byteStream(), MAX_NODE_DESCRIPTOR_BYTES)
                ?.takeIf { it.isNotEmpty() }
        }
    }

    private companion object {
        const val NODE_DESCRIPTOR_MEDIA_TYPE = "application/cbor"
        const val MAX_NODE_DESCRIPTOR_BYTES = 1_024L
        const val NODE_PUBLIC_KEY_BYTES = 32
        const val CAPABILITY_BYTES = 32
        const val ACCOUNT_CONTEXT_BYTES = 32
    }
}
