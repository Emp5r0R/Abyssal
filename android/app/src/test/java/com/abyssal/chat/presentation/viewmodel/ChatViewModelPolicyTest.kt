package com.abyssal.chat.presentation.viewmodel

import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.PrekeyLease
import com.abyssal.chat.domain.model.RecipientIdentity
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.DirectoryEvidenceStatus
import com.abyssal.chat.domain.model.DirectoryStamp
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.SessionInactivityPolicy
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.SenderClient
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.repository.IAppUpdateService
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IDisguiseManager
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.IIdentityService
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import com.abyssal.chat.domain.repository.INodeConfigService
import com.abyssal.chat.domain.repository.OutboundSendResult
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.CancellationException
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainCoroutineDispatcher
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import org.json.JSONObject
import org.junit.Before
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatViewModelPolicyTest {
    private companion object {
        val TEST_DIRECTORY_STAMP = DirectoryStamp(
            nodeId = "node-1",
            revision = 1u,
            digest = "A".repeat(43)
        )
    }

    @Before
    fun installMainDispatcherForConstructorFixtures() {
        // Local Android tests do not provide a real android.os.Looper, while
        // ViewModel's production scope correctly binds to Dispatchers.Main.
        // Replace only the coroutines loader for these constructor-backed
        // transaction fixtures; production dispatching remains untouched.
        val loader = Class.forName(
            "kotlinx.coroutines.internal.MainDispatcherLoader",
            true,
            ChatViewModel::class.java.classLoader
        )
        val field = loader.getDeclaredField("dispatcher")
        field.isAccessible = true
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        val base = unsafeClass.getMethod("staticFieldBase", java.lang.reflect.Field::class.java)
            .invoke(unsafe, field)
        val offset = unsafeClass.getMethod("staticFieldOffset", java.lang.reflect.Field::class.java)
            .invoke(unsafe, field)
        unsafeClass.getMethod(
            "putObject",
            Any::class.java,
            Long::class.javaPrimitiveType,
            Any::class.java
        ).invoke(unsafe, base, offset, TestMainDispatcher)
    }

    private object TestMainDispatcher : MainCoroutineDispatcher() {
        override val immediate: MainCoroutineDispatcher
            get() = this

        override fun dispatch(
            context: kotlin.coroutines.CoroutineContext,
            block: Runnable
        ) {
            Dispatchers.Default.dispatch(context, block)
        }
    }

    @Test
    fun soloForumCanStoreTextLocallyWithoutCryptoRecipients() {
        assertTrue(isLocalOnlyForum("forum_general", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", listOf(recipient("Bob"))))
        assertFalse(isLocalOnlyForum("dm_bob", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", null))
    }

    @Test
    fun unverifiedDirectPathsRejectBeforeTransportAndForumsRemainAllowed() = runBlocking {
        val sender = nativeIdentity(13)
        val bob = nativeIdentity(14)
        val user = User("Alice", sender.publicKey(), sender.prekeyId())
        val direct = ChatSession(
            id = "dm_bob",
            name = "Bob",
            isForum = false,
            lastMessage = null,
            unreadCount = 0,
            selfDestructTimerSec = 5
        )
        val forum = direct.copy(id = "forum_ops", name = "Operations", isForum = true)
        val attachment = attachmentMessage(70).copy(sender = "Bob", receiver = "Alice")
        val attachmentCalls = AtomicLong(0L)
        val markReadCalls = AtomicLong(0L)
        val activeSession = nodeSession("node-dm", "token-dm")
        val probe = TransactionTransportProbe(
            cipher = sender,
            leases = emptyList(),
            sendResult = OutboundSendResult.ACCEPTED,
            presence = listOf(UserPresence("Bob", true, bob.publicKey(), bob.prekeyId()))
        )
        val viewModel = transactionViewModel(
            payloadCipher = sender,
            user = user,
            probe = probe,
            sessions = listOf(forum, direct),
            messages = mapOf("dm_bob" to listOf(attachment)),
            attachmentCalls = attachmentCalls,
            markReadCalls = markReadCalls,
            activeSession = activeSession
        )

        try {
            viewModel.sessions.first { it.size == 2 }
            viewModel.serverStatus.first { it.state == "CONNECTED" }
            setActiveChatId(viewModel, "dm_bob")
            viewModel.activeMessages.first { it.singleOrNull()?.id == attachment.id }

            assertFalse(viewModel.directTrust.value.verified)
            assertFalse(invokeIsDirectChatTrusted(viewModel, "dm_bob"))
            assertTrue(invokeIsDirectChatTrusted(viewModel, "forum_ops"))
            assertFalse(invokeIsDirectChatTrusted(viewModel, "dm_missing"))

            viewModel.sendMessage("must be verified", 5)
            val bytes = byteArrayOf(1, 2, 3)
            viewModel.sendAttachment(
                mediaType = "FILE",
                fileName = "secret.bin",
                mimeType = "application/octet-stream",
                bytes = bytes,
                selfDestructSec = 5,
                oneTimeView = false,
                deleteAfterDownload = false
            )
            viewModel.viewAttachment(attachment)
            viewModel.markMessageAsRead(attachment.id)
            delay(100)

            assertArrayEquals(ByteArray(3), bytes)
            assertEquals(0L, attachmentCalls.get())
            assertEquals(1L, markReadCalls.get())
            assertTrue(probe.events.isEmpty())
        } finally {
            viewModel.clear()
            user.publicKey.fill(0)
            sender.clear()
            bob.clear()
            attachment.attachmentKey?.fill(0)
            attachment.senderPublicKey?.fill(0)
        }
    }

    @Test
    fun connectionGenerationInvalidationFailsClosedAfterAcceptedTransportResult() = runBlocking {
        val sender = nativeIdentity(15)
        val bob = nativeIdentity(16)
        establishReciprocalSession(sender, bob)
        val user = User("Alice", sender.publicKey(), sender.prekeyId())
        val bobRecipient = recipientFromNative("Bob", bob)
        val connectionGeneration = AtomicLong(1L)
        val probe = TransactionTransportProbe(
            cipher = sender,
            leases = emptyList(),
            sendResult = OutboundSendResult.ACCEPTED,
            connectionGeneration = connectionGeneration,
            invalidateAfterSend = true
        )
        val viewModel = transactionViewModel(sender, user, probe)
        val stamp = invokeCaptureSessionStamp(viewModel)

        try {
            assertEquals(
                OutboundSendResult.AMBIGUOUS,
                invokeSendEncryptedMetadata(
                    viewModel,
                    stamp,
                    chatId = "dm_bob",
                    messageId = "message-connection-race",
                    metadata = textMetadata("message-connection-race"),
                    recipients = listOf(bobRecipient)
                )
            )
            assertEquals(2L, connectionGeneration.get())
            assertEquals(listOf("send:encrypted", "disconnect"), probe.events)
            assertNull(viewModel.currentUser.value)
            assertNull(sender.stateSnapshot())
        } finally {
            wipeSessionStamp(stamp)
            viewModel.clear()
            wipeUserAndCipher(user, sender, bobRecipient, bob)
        }
    }

    @Test
    fun decryptedAttachmentMustMatchAuthenticatedMessageSize() {
        assertTrue(isDecryptedAttachmentSizeValid(actualBytes = 4L, expectedBytes = 4L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 3L, expectedBytes = 4L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 0L, expectedBytes = 0L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 11L, expectedBytes = 11L, maxBytes = 10L))
    }

    @Test
    fun inboundInnerMessageIdMustMatchAuthenticatedEnvelope() {
        val valid = JSONObject().put("id", "message-1")
        assertTrue(matchesAuthoritativeMessageId(valid, "message-1"))
        assertFalse(matchesAuthoritativeMessageId(valid, "message-2"))
        assertFalse(matchesAuthoritativeMessageId(JSONObject().put("id", ""), "message-1"))
        assertFalse(matchesAuthoritativeMessageId(JSONObject(), "message-1"))
        assertFalse(matchesAuthoritativeMessageId(null, "message-1"))
    }

    @Test
    fun inboundInnerDirectoryEvidenceMustMatchBeforeAcknowledgement() {
        val payload = IncomingTransportPayload(
            chatId = "forum_alpha",
            messageId = "message-1",
            version = 9,
            identityPublicKey = ByteArray(608),
            nonce = ByteArray(12),
            ciphertext = byteArrayOf(1),
            signature = ByteArray(64),
            wrappedKey = byteArrayOf(2),
            senderUsername = "Bob",
            senderPublicKey = ByteArray(608),
            directoryNodeId = "node-1",
            directoryRevision = 7u,
            directoryDigest = "A".repeat(43)
        )
        val valid = JSONObject()
            .put("directory_node_id", "node-1")
            .put("directory_revision", 7L)
            .put("directory_digest", "A".repeat(43))
        assertTrue(invokeMatchesDirectoryStamp(valid, payload))
        assertFalse(invokeMatchesDirectoryStamp(valid.put("directory_revision", 8L), payload))
        assertFalse(invokeMatchesDirectoryStamp(valid.put("directory_revision", 7L).put("directory_node_id", "node-2"), payload))
        assertFalse(invokeMatchesDirectoryStamp(JSONObject().put("directory_node_id", "node-1"), payload))
        payload.identityPublicKey.fill(0)
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.signature.fill(0)
        payload.wrappedKey.fill(0)
        payload.senderPublicKey.fill(0)
    }

    @Test
    fun readReceiptMustBindItsInnerIdToTheRelayMessageId() {
        val receipt = JSONObject()
            .put("kind", "read_receipt")
            .put("id", "receipt-1")
            .put("message_id", "message-1")

        assertTrue(matchesAuthoritativeMessageId(receipt, "receipt-1"))
        assertFalse(matchesAuthoritativeMessageId(receipt, "receipt-2"))
    }

    @Test
    fun inboundTextRequiresExactSenderClientTagAndPreservesOrigin() {
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User(username = "Alice", publicKey = ByteArray(608)))
        setOwnMessageIds(viewModel)
        setSessions(viewModel, emptyList())

        fun taggedPayload(senderClient: String?): JSONObject =
            JSONObject()
                .put("kind", "text")
                .put("id", "message-1")
                .put("sender", "Bob")
                .put("content", "origin probe")
                .apply { senderClient?.let { put("sender_client", it) } }

        val webTagged = invokeParseIncomingMessage(
            viewModel, "dm_bob", "message-1", taggedPayload("web").toString(), "Bob", ByteArray(608)
        )
        assertNotNull(webTagged)
        assertEquals(SenderClient.WEB, webTagged?.senderClient)

        val androidTagged = invokeParseIncomingMessage(
            viewModel, "dm_bob", "message-1", taggedPayload("android").toString(), "Bob", ByteArray(608)
        )
        assertNotNull(androidTagged)
        assertEquals(SenderClient.ANDROID, androidTagged?.senderClient)

        assertNull(
            invokeParseIncomingMessage(
                viewModel, "dm_bob", "message-1", taggedPayload(null).toString(), "Bob", ByteArray(608)
            )
        )
        assertNull(
            invokeParseIncomingMessage(
                viewModel, "dm_bob", "message-1", taggedPayload("desktop").toString(), "Bob", ByteArray(608)
            )
        )
        assertNull(
            invokeParseIncomingMessage(
                viewModel, "dm_bob", "message-1", taggedPayload("WEB").toString(), "Bob", ByteArray(608)
            )
        )
    }

    @Test
    fun accountEntryGateRejectsConcurrentAndCanceledResults() {
        val activeJob = Job()
        assertFalse(canStartAccountEntry(activeJob))
        activeJob.cancel()
        assertTrue(canStartAccountEntry(activeJob))

        val valid = IdentityValidationResult(
            accepted = true,
            token = "token",
            publicKey = ByteArray(608),
            prekeyId = "prekey"
        )
        assertTrue(canInstallAccountEntryResult(true, valid))
        assertFalse(canInstallAccountEntryResult(false, valid))
        valid.publicKey?.fill(0)
    }

    @Test
    fun calculatorResultCannotOverwriteNewerInputOrCancelledJob() {
        assertTrue(canApplyCalculatorEvaluation(4L, 4L, true))
        assertFalse(canApplyCalculatorEvaluation(3L, 4L, true))
        assertFalse(canApplyCalculatorEvaluation(4L, 4L, false))
    }

    @Test
    fun acknowledgementFailuresAreContainedAndNativeBuffersAreWiped() = runBlocking {
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { throw IllegalStateException("snapshot") },
                signAction = { error("signer must not run") },
                send = { _, _ -> error("transport must not run") }
            )
        )

        val signerState = testIdentityState(1)
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { signerState },
                signAction = { throw IllegalStateException("signer") },
                send = { _, _ -> error("transport must not run") }
            )
        )
        assertIdentityStateWiped(signerState)

        val transportState = testIdentityState(2)
        val transportSignature = ByteArray(ACK_SIGNATURE_BYTES) { 3 }
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { transportState },
                signAction = { transportSignature },
                send = { _, _ -> throw IllegalStateException("transport") }
            )
        )
        assertIdentityStateWiped(transportState)
        assertArrayEquals(ByteArray(ACK_SIGNATURE_BYTES), transportSignature)

        val canceledState = testIdentityState(4)
        var cancellationRethrown = false
        try {
            acknowledgeWithEphemeralState(
                snapshot = { canceledState },
                signAction = { throw CancellationException("cancelled") },
                send = { _, _ -> true }
            )
        } catch (_: CancellationException) {
            cancellationRethrown = true
        }
        assertTrue(cancellationRethrown)
        assertIdentityStateWiped(canceledState)

        val sendCanceledState = testIdentityState(5)
        val sendCanceledSignature = ByteArray(ACK_SIGNATURE_BYTES) { 6 }
        cancellationRethrown = false
        try {
            acknowledgeWithEphemeralState(
                snapshot = { sendCanceledState },
                signAction = { sendCanceledSignature },
                send = { _, _ -> throw CancellationException("send cancelled") }
            )
        } catch (_: CancellationException) {
            cancellationRethrown = true
        }
        assertTrue(cancellationRethrown)
        assertIdentityStateWiped(sendCanceledState)
        assertArrayEquals(ByteArray(ACK_SIGNATURE_BYTES), sendCanceledSignature)
    }

    @Test
    fun staleAckFailureCannotClearAReestablishedSameIdentitySession() = runBlocking {
        val publicKey = ByteArray(608) { 4 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Alice", publicKey))
        setSessionGeneration(viewModel, 2L)
        val stamp = newSessionStamp(
            generation = 1L,
            username = "Alice",
            identityPublicKey = publicKey.copyOf(),
            repositoryEpoch = 0uL
        )

        // The old suspended operation captured this identity before logout/relogin.
        // The new session intentionally has the same username and key.
        invokeFailClosedForIncomingAckFailure(
            viewModel,
            stamp = stamp
        )

        assertEquals(
            "A stale ACK failure must not log out the newly established session",
            User("Alice", publicKey),
            viewModel.currentUser.value
        )
        publicKey.fill(0)
    }

    @Test
    fun staleDuressEvaluationCannotBroadcastOrLogoutReplacementAccount() = runBlocking {
        val replacementKey = ByteArray(608) { 12 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Replacement", replacementKey))
        setSessionGeneration(viewModel, 2L)
        setActiveSessionPolicy(viewModel)
        installRepositoryProbe(viewModel, AtomicLong(0L))
        val wipeCalls = AtomicLong(0L)
        installTransportProbe(
            viewModel = viewModel,
            calls = AtomicLong(0L),
            connectionGeneration = AtomicLong(2L),
            wipeCalls = wipeCalls
        )
        val staleStamp = newSessionStamp(
            generation = 1L,
            username = "Original",
            identityPublicKey = ByteArray(608) { 3 },
            repositoryEpoch = 0uL,
            connectionGeneration = 1L
        )

        invokeExecuteDuressWipe(viewModel, staleStamp)

        assertEquals(0L, wipeCalls.get())
        assertEquals("Replacement", viewModel.currentUser.value?.username)
        wipeSessionStamp(staleStamp)
        replacementKey.fill(0)
    }

    @Test
    fun oldSessionStampIsInvalidAfterGenerationOrIdentityChangeAndItsCopyCanBeWiped() {
        val oldKey = ByteArray(608) { 4 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Alice", oldKey))
        setSessionGeneration(viewModel, 1L)
        setActiveSessionPolicy(viewModel)
        val repositoryEpoch = AtomicLong(0L)
        installRepositoryProbe(viewModel, repositoryEpoch)
        val transportGeneration = AtomicLong(1L)
        installTransportProbe(viewModel, AtomicLong(0L), transportGeneration)

        val stamp = invokeCaptureSessionStamp(viewModel)
        assertTrue(invokeIsSessionStampValid(viewModel, stamp))

        setSessionGeneration(viewModel, 2L)
        assertFalse(invokeIsSessionStampValid(viewModel, stamp))

        setSessionGeneration(viewModel, 1L)
        repositoryEpoch.set(1L)
        assertFalse(invokeIsSessionStampValid(viewModel, stamp))

        repositoryEpoch.set(0L)
        setCurrentUser(viewModel, User("Alice", ByteArray(608) { 5 }))
        assertFalse(invokeIsSessionStampValid(viewModel, stamp))

        val copiedKey = sessionStampKey(stamp)
        assertArrayEquals(oldKey, copiedKey)
        wipeSessionStamp(stamp)
        assertArrayEquals(ByteArray(608), copiedKey)
        oldKey.fill(0)
    }

    @Test
    fun connectionChangeInvalidatesTransportStampButNotCapturedAccountIdentity() {
        val publicKey = ByteArray(608) { 11 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Alice", publicKey))
        setSessionGeneration(viewModel, 1L)
        setActiveSessionPolicy(viewModel)
        installRepositoryProbe(viewModel, AtomicLong(0L))
        val transportGeneration = AtomicLong(20L)
        installTransportProbe(viewModel, AtomicLong(0L), transportGeneration)

        val stamp = invokeCaptureSessionStamp(viewModel)
        assertTrue(invokeIsSessionStampValid(viewModel, stamp))
        assertTrue(invokeIsAccountSessionStampValid(viewModel, stamp))

        transportGeneration.set(21L)
        assertFalse(invokeIsSessionStampValid(viewModel, stamp))
        assertTrue(invokeIsAccountSessionStampValid(viewModel, stamp))

        wipeSessionStamp(stamp)
        publicKey.fill(0)
    }

    @Test
    fun staleQueuedTextTransactionCannotReachTransportAfterSessionChange() = runBlocking {
        val oldKey = ByteArray(608) { 6 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Alice", oldKey))
        setSessionGeneration(viewModel, 1L)
        setActiveSessionPolicy(viewModel)
        setCryptoGate(viewModel)
        installRepositoryProbe(viewModel, AtomicLong(0L))
        val transportCalls = AtomicLong(0L)
        installTransportProbe(viewModel, transportCalls)

        val stamp = invokeCaptureSessionStamp(viewModel)
        setSessionGeneration(viewModel, 2L)
        setCurrentUser(viewModel, User("Alice", ByteArray(608) { 7 }))

        assertEquals(
            OutboundSendResult.NOT_SENT,
            invokeSendEncryptedMetadata(viewModel, stamp)
        )
        assertEquals(0L, transportCalls.get())
        wipeSessionStamp(stamp)
        oldKey.fill(0)
    }

    @Test
    fun staleAttachmentMetadataSkipsMetadataTransport() = runBlocking {
        val oldKey = ByteArray(608) { 8 }
        val viewModel = allocateUninitializedViewModel()
        setCurrentUser(viewModel, User("Alice", oldKey))
        setSessionGeneration(viewModel, 1L)
        setActiveSessionPolicy(viewModel)
        setCryptoGate(viewModel)
        val repositoryEpoch = AtomicLong(0L)
        installRepositoryProbe(viewModel, repositoryEpoch)
        val transportCalls = AtomicLong(0L)
        installTransportProbe(viewModel, transportCalls)

        val stamp = invokeCaptureSessionStamp(viewModel)
        setSessionGeneration(viewModel, 2L)
        setCurrentUser(viewModel, User("Alice", ByteArray(608) { 9 }))
        val attachmentMetadata = JSONObject()
            .put("kind", "attachment")
            .put("id", "5dbf06b8-fca4-46c4-8f26-5589e7024d94")
            .put("attachment_id", "123e4567-e89b-12d3-a456-426614174000")
            .toString()

        assertEquals(
            OutboundSendResult.NOT_SENT,
            invokeSendEncryptedMetadata(
                viewModel,
                stamp,
                chatId = "dm_bob",
                messageId = "5dbf06b8-fca4-46c4-8f26-5589e7024d94",
                metadata = attachmentMetadata
            )
        )
        assertEquals(0L, transportCalls.get())
        wipeSessionStamp(stamp)
        oldKey.fill(0)
    }

    @Test
    fun firstContactLeasesAllRecipientsBeforeNativeEncryptAndAcceptedCommitsWithoutRelease() =
        runBlocking {
            val sender = nativeIdentity(21)
            val bob = nativeIdentity(22)
            val carol = nativeIdentity(23)
            val senderKey = sender.publicKey()
            val user = User("Alice", senderKey, sender.prekeyId())
            val bobRecipient = recipientFromNative("Bob", bob)
            val carolRecipient = recipientFromNative("Carol", carol)
            val probe = TransactionTransportProbe(
                cipher = sender,
                leases = listOf(leaseFor("dm_ops", "message-first", "Bob", bob),
                    leaseFor("dm_ops", "message-first", "Carol", carol)),
                sendResult = OutboundSendResult.ACCEPTED
            )
            val viewModel = transactionViewModel(sender, user, probe)
            val stamp = invokeCaptureSessionStamp(viewModel)

            try {
                val result = invokeSendEncryptedMetadata(
                    viewModel,
                    stamp,
                    chatId = "dm_ops",
                    messageId = "message-first",
                    metadata = textMetadata("message-first"),
                    recipients = listOf(bobRecipient, carolRecipient)
                )

                assertEquals(OutboundSendResult.ACCEPTED, result)
                assertEquals(
                    listOf("lease:Bob:preEncrypt", "lease:Carol:preEncrypt", "send:encrypted"),
                    probe.events
                )
                assertNotNull(sender.stateSnapshot())
            } finally {
                wipeSessionStamp(stamp)
                viewModel.clear()
                wipeUserAndCipher(user, sender, bobRecipient, carolRecipient, bob, carol)
            }
        }

    @Test
    fun partialMultiRecipientAcquisitionReleasesEveryKnownLeaseBeforeReturning() = runBlocking {
        val sender = nativeIdentity(24)
        val bob = nativeIdentity(25)
        val carol = nativeIdentity(26)
        val user = User("Alice", sender.publicKey(), sender.prekeyId())
        val bobRecipient = recipientFromNative("Bob", bob)
        val carolRecipient = recipientFromNative("Carol", carol)
        val probe = TransactionTransportProbe(
            cipher = sender,
            leases = listOf(leaseFor("dm_ops", "message-partial", "Bob", bob), null),
            sendResult = OutboundSendResult.ACCEPTED
        )
        val viewModel = transactionViewModel(sender, user, probe)
        val stamp = invokeCaptureSessionStamp(viewModel)

        try {
            val result = invokeSendEncryptedMetadata(
                viewModel,
                stamp,
                chatId = "dm_ops",
                messageId = "message-partial",
                metadata = textMetadata("message-partial"),
                recipients = listOf(bobRecipient, carolRecipient)
            )

            assertNull(result)
            assertEquals(
                listOf(
                    "lease:Bob:preEncrypt",
                    "lease:Carol:preEncrypt",
                    "release:Bob:rolledBack"
                ),
                probe.events
            )
            assertNull(sender.stateSnapshot())
        } finally {
            wipeSessionStamp(stamp)
            viewModel.clear()
            wipeUserAndCipher(user, sender, bobRecipient, carolRecipient, bob, carol)
        }
    }

    @Test
    fun rejectedAndNotSentTransactionsRollbackBeforeReleasingTheirLeases() = runBlocking {
        listOf(OutboundSendResult.REJECTED, OutboundSendResult.NOT_SENT).forEachIndexed { index, outcome ->
            val sender = nativeIdentity(30 + index)
            val bob = nativeIdentity(40 + index)
            val user = User("Alice", sender.publicKey(), sender.prekeyId())
            val bobRecipient = recipientFromNative("Bob", bob)
            val messageId = "message-reject-$index"
            val probe = TransactionTransportProbe(
                cipher = sender,
                leases = listOf(leaseFor("dm_bob", messageId, "Bob", bob)),
                sendResult = outcome
            )
            val viewModel = transactionViewModel(sender, user, probe)
            val stamp = invokeCaptureSessionStamp(viewModel)

            try {
                val result = invokeSendEncryptedMetadata(
                    viewModel,
                    stamp,
                    chatId = "dm_bob",
                    messageId = messageId,
                    metadata = textMetadata(messageId),
                    recipients = listOf(bobRecipient)
                )

                assertEquals(outcome, result)
                assertEquals(
                    listOf("lease:Bob:preEncrypt", "send:encrypted", "release:Bob:rolledBack"),
                    probe.events
                )
                assertNull(sender.stateSnapshot())
            } finally {
                wipeSessionStamp(stamp)
                viewModel.clear()
                wipeUserAndCipher(user, sender, bobRecipient, bob)
            }
        }
    }

    @Test
    fun ambiguousTransactionNeverReleasesAndFailsClosed() = runBlocking {
        val sender = nativeIdentity(50)
        val bob = nativeIdentity(51)
        val user = User("Alice", sender.publicKey(), sender.prekeyId())
        val bobRecipient = recipientFromNative("Bob", bob)
        val probe = TransactionTransportProbe(
            cipher = sender,
            leases = listOf(leaseFor("dm_bob", "message-ambiguous", "Bob", bob)),
            sendResult = OutboundSendResult.AMBIGUOUS
        )
        val viewModel = transactionViewModel(sender, user, probe)
        val stamp = invokeCaptureSessionStamp(viewModel)

        try {
            val result = invokeSendEncryptedMetadata(
                viewModel,
                stamp,
                chatId = "dm_bob",
                messageId = "message-ambiguous",
                metadata = textMetadata("message-ambiguous"),
                recipients = listOf(bobRecipient)
            )

            assertEquals(OutboundSendResult.AMBIGUOUS, result)
            assertEquals(listOf("lease:Bob:preEncrypt", "send:encrypted", "disconnect"), probe.events)
            assertTrue(viewModel.currentUser.value == null)
            assertNull(sender.stateSnapshot())
        } finally {
            wipeSessionStamp(stamp)
            viewModel.clear()
            wipeUserAndCipher(user, sender, bobRecipient, bob)
        }
    }

    @Test
    fun establishedSessionUsesCatalogIdentityWithoutRequestingLease() = runBlocking {
        val sender = nativeIdentity(60)
        val bob = nativeIdentity(61)
        establishReciprocalSession(sender, bob)
        assertFalse(sender.requiresPrekey("Bob"))
        val user = User("Alice", sender.publicKey(), sender.prekeyId())
        val bobRecipient = recipientFromNative("Bob", bob)
        val probe = TransactionTransportProbe(
            cipher = sender,
            leases = emptyList(),
            sendResult = OutboundSendResult.ACCEPTED
        )
        val viewModel = transactionViewModel(sender, user, probe)
        val stamp = invokeCaptureSessionStamp(viewModel)

        try {
            val result = invokeSendEncryptedMetadata(
                viewModel,
                stamp,
                chatId = "dm_bob",
                messageId = "message-established",
                metadata = textMetadata("message-established"),
                recipients = listOf(bobRecipient)
            )

            assertEquals(OutboundSendResult.ACCEPTED, result)
            assertEquals(listOf("send:encrypted"), probe.events)
        } finally {
            wipeSessionStamp(stamp)
            viewModel.clear()
            wipeUserAndCipher(user, sender, bobRecipient, bob)
        }
    }

    @Test
    fun staleAttachmentSaveSkipsRepositoryAndWipesSecrets() = runBlocking {
        val message = attachmentMessage(1)
        var saveCalls = 0

        val saved = saveAcceptedAttachmentIfCurrent(
            isCurrent = { false },
            save = {
                saveCalls += 1
                true
            },
            wipe = { wipeMessageSecretsForTest(message) }
        )

        assertFalse(saved)
        assertEquals(0, saveCalls)
        assertMessageSecretsWiped(message)
    }

    @Test
    fun rejectedAttachmentSaveWipesSecrets() = runBlocking {
        val message = attachmentMessage(2)

        val saved = saveAcceptedAttachmentIfCurrent(
            isCurrent = { true },
            save = { false },
            wipe = { wipeMessageSecretsForTest(message) }
        )

        assertFalse(saved)
        assertMessageSecretsWiped(message)
    }

    @Test
    fun attachmentSaveWipesSecretsWhenSessionChangesAfterRepositoryWrite() = runBlocking {
        val message = attachmentMessage(3)
        var currentChecks = 0
        var saveCalls = 0

        val saved = saveAcceptedAttachmentIfCurrent(
            isCurrent = { ++currentChecks == 1 },
            save = {
                saveCalls += 1
                true
            },
            wipe = { wipeMessageSecretsForTest(message) }
        )

        assertFalse(saved)
        assertEquals(1, saveCalls)
        assertEquals(2, currentChecks)
        assertMessageSecretsWiped(message)
    }

    @Test
    fun acceptedAttachmentSaveRetainsSecretsForTheCaller() = runBlocking {
        val message = attachmentMessage(4)
        val originalKey = message.attachmentKey!!.copyOf()
        val originalSenderKey = message.senderPublicKey!!.copyOf()

        val saved = saveAcceptedAttachmentIfCurrent(
            isCurrent = { true },
            save = { true },
            wipe = { wipeMessageSecretsForTest(message) }
        )

        assertTrue(saved)
        assertArrayEquals(originalKey, message.attachmentKey)
        assertArrayEquals(originalSenderKey, message.senderPublicKey)
    }

    @Test
    fun attachmentSaveFailurePreservesOriginalExceptionAndWipesWithSuppressedCleanup() = runBlocking {
        val message = attachmentMessage(5)
        val saveFailure = IllegalStateException("save failed")
        val cleanupFailure = IllegalArgumentException("cleanup failed")

        val thrown = runCatching {
            saveAcceptedAttachmentIfCurrent(
                isCurrent = { true },
                save = { throw saveFailure },
                wipe = {
                    wipeMessageSecretsForTest(message)
                    throw cleanupFailure
                }
            )
        }.exceptionOrNull()

        assertSame(saveFailure, thrown)
        assertTrue(thrown!!.suppressed.single() === cleanupFailure)
        assertMessageSecretsWiped(message)
    }

    @Test
    fun attachmentValidityFailureWipesSecretsAndPreservesOriginalException() = runBlocking {
        val message = attachmentMessage(6)
        val validityFailure = IllegalStateException("session validity failed")
        var saveCalls = 0

        val thrown = runCatching {
            saveAcceptedAttachmentIfCurrent(
                isCurrent = { throw validityFailure },
                save = {
                    saveCalls += 1
                    true
                },
                wipe = { wipeMessageSecretsForTest(message) }
            )
        }.exceptionOrNull()

        assertSame(validityFailure, thrown)
        assertEquals(0, saveCalls)
        assertMessageSecretsWiped(message)
    }

    @Test
    fun externalPickerCallbacksAreGenerationScopedAndExpire() {
        val gate = ExternalSystemUiTokenGate()
        val first = gate.begin()
        val second = gate.begin()

        assertFalse(gate.end(first))
        assertTrue(gate.activeToken() == second)
        assertTrue(gate.end(second))
        assertFalse(gate.end(second))

        val expired = gate.begin()
        assertTrue(gate.expire(expired))
        assertFalse(gate.end(expired))
    }

    @Test
    fun teardownClearsIdentitySessionAndWipesCurrentUserKey() {
        val publicKey = ByteArray(608) { 7 }
        var logoutCalled = false
        var nodeCleared = false

        clearClientIdentity(
            currentUser = User("Alice", publicKey),
            logout = { logoutCalled = true },
            clearNodeSession = { nodeCleared = true }
        )

        assertTrue(logoutCalled)
        assertTrue(nodeCleared)
        assertArrayEquals(ByteArray(608), publicKey)
    }

    @Test
    fun teardownStillClearsOtherStateWhenAServiceThrows() {
        val publicKey = ByteArray(608) { 9 }
        var nodeCleared = false

        clearClientIdentity(
            currentUser = User("Alice", publicKey),
            logout = { error("logout failure") },
            clearNodeSession = { nodeCleared = true }
        )

        assertTrue(nodeCleared)
        assertArrayEquals(ByteArray(608), publicKey)
    }

    @Test
    fun uploadedAttachmentIsDeletedUntilMetadataIsAccepted() {
        assertTrue(shouldDeleteUploadedAttachment("123e4567-e89b-12d3-a456-426614174000", false))
        assertFalse(shouldDeleteUploadedAttachment("123e4567-e89b-12d3-a456-426614174000", true))
        assertFalse(
            shouldDeleteUploadedAttachment(
                "123e4567-e89b-12d3-a456-426614174000",
                metadataAccepted = false,
                metadataAmbiguous = true
            )
        )
        assertFalse(shouldDeleteUploadedAttachment(null, false))
    }

    @Test
    fun attachmentCoordinatorCancelsConcurrentJobsAndCleansPreStartCancellation() = runBlocking {
        val coordinator = AttachmentOperationCoordinator()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val firstStarted = CompletableDeferred<Unit>()
        val secondStarted = CompletableDeferred<Unit>()
        val firstCancelled = CompletableDeferred<Unit>()
        val secondCancelled = CompletableDeferred<Unit>()

        val first = coordinator.launch(scope) {
            try {
                firstStarted.complete(Unit)
                delay(Long.MAX_VALUE)
            } finally {
                firstCancelled.complete(Unit)
            }
        }
        val second = coordinator.launch(scope) {
            try {
                secondStarted.complete(Unit)
                delay(Long.MAX_VALUE)
            } finally {
                secondCancelled.complete(Unit)
            }
        }

        firstStarted.await()
        secondStarted.await()
        coordinator.invalidateOperations()
        coordinator.cancelAll()
        first.join()
        second.join()
        assertTrue(firstCancelled.isCompleted)
        assertTrue(secondCancelled.isCompleted)

        var preStartCleanupCalls = 0
        val pending = coordinator.launch(
            scope = scope,
            onCancelledBeforeStart = { preStartCleanupCalls++ },
            startImmediately = false
        ) { error("pre-start body must not run") }
        pending.cancelAndJoin()
        assertEquals(1, preStartCleanupCalls)
        scope.cancel()
    }

    @Test
    fun attachmentCoordinatorKeepsProgressOwnedByNewestOperationOnly() {
        val coordinator = AttachmentOperationCoordinator()
        val first = coordinator.beginOperation()
        val second = coordinator.beginOperation()

        assertFalse(coordinator.ownsProgress(first))
        assertTrue(coordinator.ownsProgress(second))

        coordinator.invalidateOperations()
        assertFalse(coordinator.ownsProgress(second))
    }

    @Test
    fun unacceptedCleanupUsesCapturedSessionAndRetainsAcceptedOrAmbiguousUploads() = runBlocking {
        val sessionA = nodeSession("node-a", "token-a")
        val sessionB = nodeSession("node-b", "token-b")
        var deletedSession: NodeSession? = null
        val attachmentId = "123e4567-e89b-12d3-a456-426614174000"

        assertTrue(
            deleteUnacceptedUploadedAttachment(
                session = sessionA,
                uploadedAttachmentId = attachmentId,
                metadataAccepted = false,
                metadataAmbiguous = false,
                delete = { session, _ ->
                    deletedSession = session
                    true
                }
            )
        )
        assertEquals(sessionA, deletedSession)
        assertFalse(
            deleteUnacceptedUploadedAttachment(
                session = sessionB,
                uploadedAttachmentId = attachmentId,
                metadataAccepted = true,
                metadataAmbiguous = false,
                delete = { _, _ -> error("accepted metadata must be retained") }
            )
        )
        assertFalse(
            deleteUnacceptedUploadedAttachment(
                session = sessionB,
                uploadedAttachmentId = attachmentId,
                metadataAccepted = false,
                metadataAmbiguous = true,
                delete = { _, _ -> error("ambiguous metadata must be retained") }
            )
        )
    }

    @Test
    fun attachmentMetadataMatchesWebWireFieldsWithoutLegacyCryptoId() {
        val key = ByteArray(32) { it.toByte() }
        val message = Message(
            id = "5dbf06b8-fca4-46c4-8f26-5589e7024d94",
            sender = "You",
            receiver = "Bob",
            content = "report.pdf",
            timestampMs = 1L,
            selfDestructDurationSec = 30,
            isMedia = true,
            mediaType = "FILE",
            attachmentId = "123e4567-e89b-12d3-a456-426614174000",
            attachmentCipherVersion = ATTACHMENT_CIPHER_VERSION,
            attachmentKey = key,
            attachmentName = "report.pdf",
            attachmentMimeType = "application/pdf",
            attachmentSizeBytes = 4L
        )

        try {
            val json = attachmentMetadataJson(message, "Alice")

            assertEquals("attachment", json.optString("kind"))
            assertEquals(message.id, json.optString("id"))
            assertEquals("android", json.optString("sender_client"))
            assertEquals(ATTACHMENT_CIPHER_VERSION, json.optInt("attachment_cipher_version"))
            assertTrue(json.optString("attachment_key_b64").matches(Regex("^[A-Za-z0-9_-]{43}$")))
            assertFalse(json.has("attachment_crypto_id"))
        } finally {
            key.fill(0)
        }
    }

    private fun transactionViewModel(
        payloadCipher: InMemoryPayloadCipher,
        user: User,
        probe: TransactionTransportProbe,
        sessions: List<com.abyssal.chat.domain.model.ChatSession> = emptyList(),
        messages: Map<String, List<Message>> = emptyMap(),
        attachmentCalls: AtomicLong? = null,
        markReadCalls: AtomicLong? = null,
        activeSession: NodeSession? = null
    ): ChatViewModel {
        val identityService = proxy(IIdentityService::class.java) { method ->
            when (method.name) {
                "getCurrentUser" -> null
                "revokeSession" -> false
                else -> Unit
            }
        }
        val nodeConfig = proxy(INodeConfigService::class.java) { method ->
            when (method.name) {
                "getActiveSession" -> activeSession
                "normalizeNodeUrl" -> error("normalizeNodeUrl must not run")
                else -> Unit
            }
        }
        val repository = proxyWithArgs(IMessageRepository::class.java) { method, args ->
            when {
                method.name == "getChatSessions" -> flowOf(sessions)
                method.name == "getMessages" -> flowOf(messages[args?.getOrNull(0) as? String].orEmpty())
                method.name.startsWith("markAsReadIfCurrent") -> {
                    markReadCalls?.incrementAndGet()
                    true
                }
                // Kotlin ULong is represented as a primitive/boxed Long at
                // this Java proxy boundary (the method name is mangled).
                else -> if (method.name.startsWith("currentEpoch")) 0L else Unit
            }
        }
        val sender = proxy(IMessageSender::class.java) { Unit }
        val attachmentService = proxy(IEncryptedAttachmentService::class.java) { method ->
            if (attachmentCalls != null && method.name in setOf(
                    "uploadEncryptedAttachment",
                    "downloadEncryptedAttachment",
                    "deleteUploadedAttachment",
                    "completeAttachmentDownload",
                    "releaseAttachmentDownloadClaim",
                    "saveDecryptedAttachment"
                )
            ) attachmentCalls.incrementAndGet()
            else Unit
        }
        val disguiseManager = proxy(IDisguiseManager::class.java) { method ->
            when (method.name) {
                "isDisguiseEnabled" -> false
                else -> Unit
            }
        }
        val updateService = proxy(IAppUpdateService::class.java) { Unit }
        val viewModel = ChatViewModel(
            identityService = identityService,
            nodeConfigService = nodeConfig,
            messageRepository = repository,
            messageSender = sender,
            chatTransport = probe.transport,
            attachmentService = attachmentService,
            disguiseManager = disguiseManager,
            appUpdateService = updateService,
            payloadCipher = payloadCipher
        )
        setCurrentUser(viewModel, user)
        setSessionGeneration(viewModel, 1L)
        setActiveSessionPolicy(viewModel)
        return viewModel
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> proxy(type: Class<T>, handler: (Method) -> Any?): T =
        Proxy.newProxyInstance(
            type.classLoader,
            arrayOf(type)
        ) { _, method, _ -> handler(method) } as T

    @Suppress("UNCHECKED_CAST")
    private fun <T> proxyWithArgs(
        type: Class<T>,
        handler: (Method, Array<out Any?>?) -> Any?
    ): T =
        Proxy.newProxyInstance(
            type.classLoader,
            arrayOf(type)
        ) { _, method, args -> handler(method, args) } as T

    private fun nativeIdentity(fill: Int): InMemoryPayloadCipher = InMemoryPayloadCipher().also {
        val exportKey = ByteArray(64) { fill.toByte() }
        val context = "ABYSSAL_IDENTITY_V2:node:CODE-12345678".encodeToByteArray()
        try {
            val material = it.createIdentity(exportKey, context)
            material.publicKey.fill(0)
            material.envelope.fill(0)
        } finally {
            exportKey.fill(0)
            context.fill(0)
        }
    }

    private fun recipientFromNative(
        username: String,
        cipher: InMemoryPayloadCipher
    ): RecipientIdentity = RecipientIdentity(
        username = username,
        publicKey = cipher.publicKey(),
        prekeyId = cipher.prekeyId()
    )

    private fun leaseFor(
        chatId: String,
        messageId: String,
        username: String,
        cipher: InMemoryPayloadCipher
    ): PrekeyLease = PrekeyLease(
        chatId = chatId,
        messageId = messageId,
        recipientUsername = username,
        recipientPublicKey = cipher.publicKey(),
        prekeyId = cipher.prekeyId(),
        expiresAtMs = 1L,
        connectionGeneration = 1L
    )

    private fun establishReciprocalSession(
        sender: InMemoryPayloadCipher,
        receiver: InMemoryPayloadCipher
    ) {
        val senderPublic = sender.publicKey()
        val receiverPublic = receiver.publicKey()
        try {
            // A peer's first-contact frame is enough to install the sender's
            // established catalog entry. The reply path is intentionally not
            // part of this policy fixture; it would exercise a second native
            // ratchet transition rather than the lease decision under test.
            val first = receiver.encrypt(
                "dm_bob",
                "setup-one",
                "Bob",
                byteArrayOf(1),
                listOf(RecipientIdentity("Alice", senderPublic, sender.prekeyId()))
            )
            receiver.commitOutbound(first.messageId, first.stateRevision)
            sender.decrypt(
                incomingFrom(first, receiverPublic, "Bob", "Alice"),
                "Alice"
            ).plaintext.fill(0)
            wipePayload(first)
        } finally {
            senderPublic.fill(0)
            receiverPublic.fill(0)
        }
    }

    private fun incomingFrom(
        payload: EncryptedTransportPayload,
        senderPublicKey: ByteArray,
        senderUsername: String,
        recipientUsername: String
    ): IncomingTransportPayload {
        val envelope = payload.envelopes.single {
            it.recipientUsername == recipientUsername
        }
        return IncomingTransportPayload(
            chatId = "dm_bob",
            messageId = payload.messageId,
            version = payload.version,
            identityPublicKey = payload.identityPublicKey,
            nonce = payload.nonce,
            ciphertext = payload.ciphertext,
            signature = envelope.signature,
            wrappedKey = envelope.wrappedKey,
            senderUsername = senderUsername,
            senderPublicKey = senderPublicKey,
            prekeyId = envelope.prekeyId,
            isPrekey = envelope.isPrekey,
            directoryNodeId = payload.directoryNodeId,
            directoryRevision = payload.directoryRevision,
            directoryDigest = payload.directoryDigest
        )
    }

    private fun wipePayload(payload: EncryptedTransportPayload) {
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.identityEnvelope.fill(0)
        payload.identityPublicKey.fill(0)
        payload.stateSignature.fill(0)
        payload.envelopes.forEach {
            it.wrappedKey.fill(0)
            it.signature.fill(0)
        }
    }

    private fun wipeUserAndCipher(
        user: User,
        sender: InMemoryPayloadCipher,
        vararg recipients: Any
    ) {
        user.publicKey.fill(0)
        sender.clear()
        recipients.forEach { value ->
            when (value) {
                is RecipientIdentity -> value.publicKey.fill(0)
                is InMemoryPayloadCipher -> value.clear()
            }
        }
    }

    private class TransactionTransportProbe(
        private val cipher: InMemoryPayloadCipher,
        private val leases: List<PrekeyLease?>,
        private val sendResult: OutboundSendResult,
        private val connectionGeneration: AtomicLong = AtomicLong(1L),
        private val invalidateAfterSend: Boolean = false,
        private val presence: List<com.abyssal.chat.domain.model.UserPresence> = emptyList()
    ) {
        val events = mutableListOf<String>()
        private var leaseIndex = 0

        val transport: IChatTransport = Proxy.newProxyInstance(
            IChatTransport::class.java.classLoader,
            arrayOf(IChatTransport::class.java)
        ) { _, method, args ->
            when (method.name) {
                "currentConnectionGeneration" -> connectionGeneration.get()
                "runIfConnectionCurrent" -> {
                    val expected = args?.getOrNull(0) as Long
                    if (expected == connectionGeneration.get()) {
                        @Suppress("UNCHECKED_CAST")
                        (args.getOrNull(1) as Function0<Boolean>).invoke()
                    } else {
                        false
                    }
                }
                "currentDirectoryStamp" -> TEST_DIRECTORY_STAMP
                "directoryEvidenceStatus" -> DirectoryEvidenceStatus.KNOWN
                "getServerStatus" -> flowOf(ServerStatus("CONNECTED", "node", 0))
                "getPresence" -> flowOf(presence)
                "getIncomingWipeCommands" -> flowOf<Long>()
                "getIncomingPayloads" -> flowOf<IncomingTransportPayload>()
                "getRoomChanges" -> flowOf<com.abyssal.chat.domain.model.RoomChange>()
                "requestPrekeyLease" -> {
                    val username = args?.getOrNull(2) as String
                    check(cipher.stateSnapshot() == null) {
                        "native encrypt staged before its lease request"
                    }
                    events += "lease:$username:preEncrypt"
                    leases.getOrNull(leaseIndex++)
                }
                "releasePrekeyLease" -> {
                    val username = args?.getOrNull(2) as String
                    val prekeyId = args.getOrNull(3) as String
                    events += "release:$username:${if (cipher.stateSnapshot() == null) "rolledBack" else "staged"}"
                    check(prekeyId.isNotEmpty())
                    true
                }
                "sendEncryptedPayload" -> {
                    check(cipher.stateSnapshot() != null) {
                        "native encrypt did not stage before relay send"
                    }
                    events += "send:encrypted"
                    if (invalidateAfterSend) connectionGeneration.incrementAndGet()
                    sendResult
                }
                "disconnect" -> {
                    events += "disconnect"
                    Unit
                }
                else -> when (method.returnType) {
                    Boolean::class.javaPrimitiveType -> false
                    Long::class.javaPrimitiveType -> 0L
                    Int::class.javaPrimitiveType -> 0
                    else -> null
                }
            }
        } as IChatTransport
    }

    private fun allocateUninitializedViewModel(): ChatViewModel {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        return unsafeClass.getMethod("allocateInstance", Class::class.java)
            .invoke(unsafe, ChatViewModel::class.java) as ChatViewModel
    }

    private fun setCurrentUser(viewModel: ChatViewModel, user: User) {
        val field = ChatViewModel::class.java.getDeclaredField("_currentUser")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val state = MutableStateFlow<User?>(null)
        state.value = user
        field.set(viewModel, state)

        // Unsafe allocation bypasses the constructor assignment of the public
        // read-only wrapper. Keep both fields wired to the same state so this
        // fixture exercises the real session predicates instead of null setup.
        val publicField = ChatViewModel::class.java.getDeclaredField("currentUser")
        publicField.isAccessible = true
        publicField.set(viewModel, state)
    }

    private fun setSessionGeneration(viewModel: ChatViewModel, generation: Long) {
        val field = ChatViewModel::class.java.getDeclaredField("sessionGeneration")
        field.isAccessible = true
        field.set(viewModel, AtomicLong(generation))
    }

    private fun setActiveChatId(viewModel: ChatViewModel, chatId: String?) {
        val field = ChatViewModel::class.java.getDeclaredField("_activeChatId")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        (field.get(viewModel) as MutableStateFlow<String?>).value = chatId
    }

    private fun setOwnMessageIds(viewModel: ChatViewModel) {
        val field = ChatViewModel::class.java.getDeclaredField("ownMessageIds")
        field.isAccessible = true
        field.set(viewModel, LinkedHashSet<String>())
    }

    private fun setSessions(viewModel: ChatViewModel, sessions: List<ChatSession>) {
        val field = ChatViewModel::class.java.getDeclaredField("sessions")
        field.isAccessible = true
        field.set(viewModel, MutableStateFlow(sessions))
    }

    private fun invokeParseIncomingMessage(
        viewModel: ChatViewModel,
        chatId: String,
        messageId: String,
        decryptedContent: String,
        senderUsername: String,
        senderPublicKey: ByteArray
    ): Message? {
        val method = ChatViewModel::class.java.getDeclaredMethod(
            "parseIncomingMessage",
            String::class.java,
            String::class.java,
            String::class.java,
            String::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        return method.invoke(viewModel, chatId, messageId, decryptedContent, senderUsername, senderPublicKey) as Message?
    }

    private fun invokeIsDirectChatTrusted(viewModel: ChatViewModel, chatId: String): Boolean {
        val method = ChatViewModel::class.java.getDeclaredMethod(
            "isDirectChatTrusted",
            String::class.java
        )
        method.isAccessible = true
        return method.invoke(viewModel, chatId) as Boolean
    }

    private fun setActiveSessionPolicy(viewModel: ChatViewModel) {
        val field = ChatViewModel::class.java.getDeclaredField("sessionInactivityPolicy")
        field.isAccessible = true
        field.set(viewModel, SessionInactivityPolicy().also { it.start(60_000L) })
    }

    private fun setCryptoGate(viewModel: ChatViewModel) {
        val field = ChatViewModel::class.java.getDeclaredField("cryptoGate")
        field.isAccessible = true
        field.set(viewModel, Mutex())
    }

    private fun installRepositoryProbe(
        viewModel: ChatViewModel,
        epoch: AtomicLong
    ) {
        val repository = Proxy.newProxyInstance(
            IMessageRepository::class.java.classLoader,
            arrayOf(IMessageRepository::class.java)
        ) { _, method, _ ->
            when {
                method.name.startsWith("currentEpoch") -> epoch.get()
                else -> null
            }
        } as IMessageRepository
        val field = ChatViewModel::class.java.getDeclaredField("messageRepository")
        field.isAccessible = true
        field.set(viewModel, repository)
    }

    private fun newSessionStamp(
        generation: Long,
        username: String,
        identityPublicKey: ByteArray,
        repositoryEpoch: ULong,
        connectionGeneration: Long = 1L
    ): Any {
        val stampClass = Class.forName(
            "com.abyssal.chat.presentation.viewmodel.ChatViewModel\$SessionStamp"
        )
        val constructor = stampClass.declaredConstructors
            .first { it.parameterCount == 5 }
            .apply { isAccessible = true }
        return constructor.newInstance(
            generation,
            username,
            identityPublicKey,
            repositoryEpoch.toLong(),
            connectionGeneration
        )
    }

    private fun invokeCaptureSessionStamp(viewModel: ChatViewModel): Any {
        val method = ChatViewModel::class.java.getDeclaredMethod("captureSessionStamp")
        method.isAccessible = true
        return requireNotNull(method.invoke(viewModel))
    }

    private fun invokeIsSessionStampValid(viewModel: ChatViewModel, stamp: Any): Boolean {
        val method = ChatViewModel::class.java.getDeclaredMethod(
            "isSessionStampValid",
            stamp.javaClass
        )
        method.isAccessible = true
        return method.invoke(viewModel, stamp) as Boolean
    }

    private fun invokeIsAccountSessionStampValid(viewModel: ChatViewModel, stamp: Any): Boolean {
        val method = ChatViewModel::class.java.getDeclaredMethod(
            "isAccountSessionStampValid",
            stamp.javaClass
        )
        method.isAccessible = true
        return method.invoke(viewModel, stamp) as Boolean
    }

    private fun invokeMatchesDirectoryStamp(
        json: JSONObject,
        payload: IncomingTransportPayload
    ): Boolean {
        val method = ChatViewModel::class.java.getDeclaredMethod(
            "matchesDirectoryStamp",
            JSONObject::class.java,
            IncomingTransportPayload::class.java
        )
        method.isAccessible = true
        return method.invoke(allocateUninitializedViewModel(), json, payload) as Boolean
    }

    private fun sessionStampKey(stamp: Any): ByteArray {
        val field = stamp.javaClass.getDeclaredField("identityPublicKey")
        field.isAccessible = true
        return field.get(stamp) as ByteArray
    }

    private fun wipeSessionStamp(stamp: Any) {
        val method = stamp.javaClass.getDeclaredMethod("wipe")
        method.isAccessible = true
        method.invoke(stamp)
    }

    private fun textMetadata(messageId: String): String = JSONObject()
        .put("kind", "text")
        .put("id", messageId)
        .put("sender", "Alice")
        .put("content", "hello")
        .put("timestamp_ms", 1L)
        .toString()

    private suspend fun invokeSendEncryptedMetadata(
        viewModel: ChatViewModel,
        stamp: Any,
        chatId: String = "dm_bob",
        messageId: String = "message-stale",
        metadata: String = textMetadata(messageId),
        recipients: List<RecipientIdentity>? = null
    ): Any? = suspendCoroutine { continuation: Continuation<Any?> ->
        try {
            val method = ChatViewModel::class.java.getDeclaredMethod(
                "sendEncryptedMetadata",
                String::class.java,
                String::class.java,
                String::class.java,
                List::class.java,
                stamp.javaClass,
                Continuation::class.java
            )
            method.isAccessible = true
            val result = method.invoke(
                viewModel,
                chatId,
                messageId,
                metadata,
                recipients,
                stamp,
                continuation
            )
            if (result !== COROUTINE_SUSPENDED) continuation.resume(result)
        } catch (error: InvocationTargetException) {
            continuation.resumeWithException(error.targetException)
        } catch (error: Throwable) {
            continuation.resumeWithException(error)
        }
    }

    private fun installTransportProbe(
        viewModel: ChatViewModel,
        calls: AtomicLong,
        connectionGeneration: AtomicLong = AtomicLong(1L),
        wipeCalls: AtomicLong = AtomicLong(0L)
    ) {
        val transport = Proxy.newProxyInstance(
            IChatTransport::class.java.classLoader,
            arrayOf(IChatTransport::class.java)
        ) { _, method, _ ->
            if (method.name == "sendEncryptedPayload") {
                calls.incrementAndGet()
                error("stale text transaction reached transport")
            }
            if (method.name == "broadcastGlobalWipe") wipeCalls.incrementAndGet()
            when (method.name) {
                "getServerStatus" -> MutableStateFlow(ServerStatus("CONNECTED", "node", 0))
                "currentConnectionGeneration" -> connectionGeneration.get()
                "currentDirectoryStamp" -> TEST_DIRECTORY_STAMP
                "directoryEvidenceStatus" -> DirectoryEvidenceStatus.KNOWN
                else -> null
            }
        } as IChatTransport
        val field = ChatViewModel::class.java.getDeclaredField("chatTransport")
        field.isAccessible = true
        field.set(viewModel, transport)
    }

    private suspend fun invokeExecuteDuressWipe(viewModel: ChatViewModel, stamp: Any) {
        suspendCoroutine<Unit> { continuation: Continuation<Unit> ->
            try {
                val method = ChatViewModel::class.java.getDeclaredMethod(
                    "executeDuressWipe",
                    stamp.javaClass,
                    Continuation::class.java
                )
                method.isAccessible = true
                val result = method.invoke(viewModel, stamp, continuation)
                if (result !== COROUTINE_SUSPENDED) continuation.resume(Unit)
            } catch (error: InvocationTargetException) {
                continuation.resumeWithException(error.targetException)
            } catch (error: Throwable) {
                continuation.resumeWithException(error)
            }
        }
    }

    private suspend fun invokeFailClosedForIncomingAckFailure(
        viewModel: ChatViewModel,
        stamp: Any
    ) {
        suspendCoroutine<Unit> { continuation: Continuation<Unit> ->
            try {
                val method = ChatViewModel::class.java.getDeclaredMethod(
                    "failClosedForIncomingAckFailure",
                    stamp.javaClass,
                    Continuation::class.java
                )
                method.isAccessible = true
                val result = method.invoke(
                    viewModel,
                    stamp,
                    continuation
                )
                if (result !== COROUTINE_SUSPENDED) continuation.resume(Unit)
            } catch (error: InvocationTargetException) {
                continuation.resumeWithException(error.targetException)
            } catch (error: Throwable) {
                continuation.resumeWithException(error)
            }
        }
    }

    private fun recipient(username: String) = RecipientIdentity(
        username = username,
        publicKey = ByteArray(608),
        prekeyId = "prekey-1"
    )

    private fun nodeSession(nodeId: String, token: String) = NodeSession(
        endpoint = NodeEndpoint(
            inputUrl = "https://$nodeId.example",
            apiBaseUrl = "https://$nodeId.example",
            wsBaseUrl = "wss://$nodeId.example",
            displayHost = nodeId
        ),
        token = token,
        nodeId = nodeId,
        maxRoomsPerUser = 5
    )

    private fun attachmentMessage(seed: Int): Message = Message(
        id = "5dbf06b8-fca4-46c4-8f26-5589e7024d9$seed",
        sender = "You",
        receiver = "Bob",
        content = "report.pdf",
        timestampMs = 1L,
        selfDestructDurationSec = 30,
        isMedia = true,
        mediaType = "FILE",
        attachmentId = "123e4567-e89b-12d3-a456-42661417400$seed",
        attachmentCipherVersion = ATTACHMENT_CIPHER_VERSION,
        attachmentKey = ByteArray(32) { (seed + it).toByte() },
        attachmentName = "report.pdf",
        attachmentMimeType = "application/pdf",
        attachmentSizeBytes = 4L,
        senderPublicKey = ByteArray(608) { (seed + it).toByte() }
    )

    private fun wipeMessageSecretsForTest(message: Message) {
        message.attachmentKey!!.fill(0)
        message.senderPublicKey!!.fill(0)
    }

    private fun assertMessageSecretsWiped(message: Message) {
        assertArrayEquals(ByteArray(message.attachmentKey!!.size), message.attachmentKey)
        assertArrayEquals(ByteArray(message.senderPublicKey!!.size), message.senderPublicKey)
    }

    private fun testIdentityState(seed: Int) = IdentityStateSnapshot(
        revision = seed.toULong(),
        envelope = ByteArray(4) { seed.toByte() },
        identityPublicKey = ByteArray(4) { (seed + 1).toByte() },
        prekeyId = "prekey-$seed",
        stateSignature = ByteArray(4) { (seed + 2).toByte() }
    )

    private fun assertIdentityStateWiped(state: IdentityStateSnapshot) {
        assertArrayEquals(ByteArray(state.envelope.size), state.envelope)
        assertArrayEquals(ByteArray(state.identityPublicKey.size), state.identityPublicKey)
        assertArrayEquals(ByteArray(state.stateSignature.size), state.stateSignature)
    }
}
