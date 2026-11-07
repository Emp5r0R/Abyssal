package com.abyssal.chat.data.network.v11

import com.abyssal.chat.domain.model.TransportKeys
import okhttp3.Call
import okhttp3.Request
import okhttp3.Response
import uniffi.abyssal_core.ControlAttestationInput
import uniffi.abyssal_core.ControlClientExchange
import uniffi.abyssal_core.ControlResponse

/** Size of every sealed control request and reply. */
internal const val CONTROL_RECORD_BYTES = 4_170L

private val WS_TICKET_REGEX = Regex("^[A-Za-z0-9_-]{43}$")

internal interface ControlExchange : AutoCloseable {
    fun requestBytes(): ByteArray
    fun openResponse(reply: ByteArray): ControlResponse
}

internal interface ControlExchanges {
    fun issueWsTicket(keys: TransportKeys, attestation: ControlAttestationInput): ControlExchange
    fun logout(keys: TransportKeys): ControlExchange
}

internal object UniffiControlExchanges : ControlExchanges {
    private class Wrapped(private val exchange: ControlClientExchange) : ControlExchange {
        override fun requestBytes() = exchange.requestBytes()
        override fun openResponse(reply: ByteArray) = exchange.openResponse(reply)
        override fun close() = exchange.close()
    }

    override fun issueWsTicket(keys: TransportKeys, attestation: ControlAttestationInput): ControlExchange = Wrapped(
        ControlClientExchange.issueWsTicket(keys.nodePublicKey, keys.sessionId, keys.transportRoot, attestation)
    )

    override fun logout(keys: TransportKeys): ControlExchange =
        Wrapped(ControlClientExchange.logout(keys.nodePublicKey, keys.sessionId, keys.transportRoot))
}

/** How a WebSocket ticket request ended. */
internal sealed interface TicketOutcome {
    class Issued(val ticket: String, val expiresInSec: Int) : TicketOutcome

    /** A refusal the client must not retry; [state] is the transport's terminal status. */
    class Terminal(val state: String) : TicketOutcome

    /** A network error, proxy error or unexpected reply: retry with backoff. */
    object Transient : TicketOutcome
}

/**
 * One WebSocket ticket request, sent through the transport's own cancellable
 * OkHttp call. The relay checks the signed build attestation here. Close it
 * once the call has ended: closing wipes the request and the exchange.
 */
internal class ControlTicketRequest(
    private val apiBaseUrl: String,
    keys: TransportKeys,
    platform: String,
    version: String,
    buildSignature: String,
    exchanges: ControlExchanges = UniffiControlExchanges
) : AutoCloseable {
    private val exchange = exchanges.issueWsTicket(keys, ControlAttestationInput(platform, version, buildSignature))
    private val record = exchange.requestBytes()

    fun httpRequest(): Request = SealedRecordHttp.request("$apiBaseUrl${SealedRecordHttp.CONTROL_PATH}", record)

    fun readOutcome(response: Response): TicketOutcome {
        val reply = SealedRecordHttp.readReply(response, CONTROL_RECORD_BYTES) ?: return TicketOutcome.Transient
        try {
            // A reply that does not open under the session keys means the relay no
            // longer knows this session (it restarted, or a newer sign-in replaced it).
            val opened = runCatching { exchange.openResponse(reply) }.getOrNull()
                ?: return TicketOutcome.Terminal(SESSION_EXPIRED)
            return when (opened) {
                is ControlResponse.WsTicket -> {
                    val expires = opened.expiresInSec.toInt()
                    if (WS_TICKET_REGEX.matches(opened.ticket) && expires in 1..30) {
                        TicketOutcome.Issued(opened.ticket, expires)
                    } else {
                        TicketOutcome.Transient
                    }
                }
                ControlResponse.BuildRejected -> TicketOutcome.Terminal(SECURITY_REJECTED)
                ControlResponse.PlatformConflict -> TicketOutcome.Terminal(PLATFORM_CONFLICT)
                else -> TicketOutcome.Transient
            }
        } finally {
            reply.fill(0)
        }
    }

    override fun close() {
        record.fill(0)
        runCatching { exchange.close() }
    }

    companion object {
        const val SESSION_EXPIRED = "SESSION_EXPIRED"
        const val SECURITY_REJECTED = "SECURITY_REJECTED"
        const val PLATFORM_CONFLICT = "PLATFORM_CONFLICT"
    }
}

/** Revokes the session on the relay. Best effort: the caller clears local state regardless. */
internal suspend fun logoutV11(
    callFactory: Call.Factory,
    apiBaseUrl: String,
    keys: TransportKeys,
    exchanges: ControlExchanges = UniffiControlExchanges
): Boolean {
    val exchange = exchanges.logout(keys)
    val record = exchange.requestBytes()
    try {
        val reply = SealedRecordHttp.post(
            callFactory,
            "$apiBaseUrl${SealedRecordHttp.CONTROL_PATH}",
            record,
            CONTROL_RECORD_BYTES
        ) ?: return false
        return try {
            runCatching { exchange.openResponse(reply) }.getOrNull() == ControlResponse.LoggedOut
        } finally {
            reply.fill(0)
        }
    } finally {
        record.fill(0)
        runCatching { exchange.close() }
    }
}
