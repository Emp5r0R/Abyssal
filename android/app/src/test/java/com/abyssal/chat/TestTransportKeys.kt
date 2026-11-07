package com.abyssal.chat

import com.abyssal.chat.domain.model.TransportKeys

/** Fixed, non-zero v11 transport keys for tests that build a NodeSession. */
fun testTransportKeys(): TransportKeys =
    TransportKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
