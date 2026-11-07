package com.abyssal.chat.data.network.v11

import com.abyssal.chat.domain.model.TransportKeys
import uniffi.abyssal_core.ControlAttestationInput
import uniffi.abyssal_core.ControlResponse

/** Control exchanges whose replies come from [answer]; records what was asked. */
internal class ScriptedControlExchanges(var answer: () -> ControlResponse) : ControlExchanges {
    @Volatile var attestation: ControlAttestationInput? = null
    @Volatile var closed = 0
    val request = ByteArray(CONTROL_RECORD_BYTES.toInt()) { 7 }

    private fun exchange() = object : ControlExchange {
        override fun requestBytes() = request
        override fun openResponse(reply: ByteArray) = answer()
        override fun close() {
            closed += 1
        }
    }

    override fun issueWsTicket(keys: TransportKeys, attestation: ControlAttestationInput): ControlExchange {
        this.attestation = attestation
        return exchange()
    }

    override fun logout(keys: TransportKeys) = exchange()
}

/**
 * A record layer whose ClientHello is "H", whose ServerHello is "S", and whose
 * records are the plaintext behind an "R" tag, so tests and a fake relay can
 * speak it without the real keys.
 */
internal class TaggedRecordLayer : WsRecordLayer {
    @Volatile var helloOpened = false
    @Volatile var closed = false
    @Volatile var rejectNext = false

    override fun clientHello() = byteArrayOf(HELLO)
    override fun openServerHello(record: ByteArray) {
        require(record.contentEquals(byteArrayOf(SERVER_HELLO)))
        helloOpened = true
    }
    override fun ready() = helloOpened
    override fun seal(plaintext: ByteArray) = byteArrayOf(RECORD) + plaintext
    override fun open(record: ByteArray): ByteArray {
        require(!rejectNext && record.firstOrNull() == RECORD)
        return record.copyOfRange(1, record.size)
    }
    override fun close() {
        closed = true
    }

    companion object {
        const val HELLO = 0x48.toByte()
        const val SERVER_HELLO = 0x53.toByte()
        const val RECORD = 0x52.toByte()
    }
}
