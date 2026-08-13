package com.abyssal.chat.presentation.viewmodel

import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.RecipientIdentity
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.SessionInactivityPolicy
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.OutboundSendResult
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatViewModelPolicyTest {
    @Test
    fun soloForumCanStoreTextLocallyWithoutCryptoRecipients() {
        assertTrue(isLocalOnlyForum("forum_general", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", listOf(recipient("Bob"))))
        assertFalse(isLocalOnlyForum("dm_bob", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", null))
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
    fun readReceiptMustBindItsInnerIdToTheRelayMessageId() {
        val receipt = JSONObject()
            .put("kind", "read_receipt")
            .put("id", "receipt-1")
            .put("message_id", "message-1")

        assertTrue(matchesAuthoritativeMessageId(receipt, "receipt-1"))
        assertFalse(matchesAuthoritativeMessageId(receipt, "receipt-2"))
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
            publicKey = ByteArray(128),
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
        val publicKey = ByteArray(128) { 4 }
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
        val replacementKey = ByteArray(128) { 12 }
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
            identityPublicKey = ByteArray(128) { 3 },
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
        val oldKey = ByteArray(128) { 4 }
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
        setCurrentUser(viewModel, User("Alice", ByteArray(128) { 5 }))
        assertFalse(invokeIsSessionStampValid(viewModel, stamp))

        val copiedKey = sessionStampKey(stamp)
        assertArrayEquals(oldKey, copiedKey)
        wipeSessionStamp(stamp)
        assertArrayEquals(ByteArray(128), copiedKey)
        oldKey.fill(0)
    }

    @Test
    fun connectionChangeInvalidatesTransportStampButNotCapturedAccountIdentity() {
        val publicKey = ByteArray(128) { 11 }
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
        val oldKey = ByteArray(128) { 6 }
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
        setCurrentUser(viewModel, User("Alice", ByteArray(128) { 7 }))

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
        val oldKey = ByteArray(128) { 8 }
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
        setCurrentUser(viewModel, User("Alice", ByteArray(128) { 9 }))
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
        val publicKey = ByteArray(128) { 7 }
        var logoutCalled = false
        var nodeCleared = false

        clearClientIdentity(
            currentUser = User("Alice", publicKey),
            logout = { logoutCalled = true },
            clearNodeSession = { nodeCleared = true }
        )

        assertTrue(logoutCalled)
        assertTrue(nodeCleared)
        assertArrayEquals(ByteArray(128), publicKey)
    }

    @Test
    fun teardownStillClearsOtherStateWhenAServiceThrows() {
        val publicKey = ByteArray(128) { 9 }
        var nodeCleared = false

        clearClientIdentity(
            currentUser = User("Alice", publicKey),
            logout = { error("logout failure") },
            clearNodeSession = { nodeCleared = true }
        )

        assertTrue(nodeCleared)
        assertArrayEquals(ByteArray(128), publicKey)
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
        val firstCancelled = CompletableDeferred<Unit>()
        val secondCancelled = CompletableDeferred<Unit>()

        val first = coordinator.launch(scope) {
            try {
                delay(Long.MAX_VALUE)
            } finally {
                firstCancelled.complete(Unit)
            }
        }
        val second = coordinator.launch(scope) {
            try {
                delay(Long.MAX_VALUE)
            } finally {
                secondCancelled.complete(Unit)
            }
        }

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
            assertEquals(ATTACHMENT_CIPHER_VERSION, json.optInt("attachment_cipher_version"))
            assertTrue(json.optString("attachment_key_b64").matches(Regex("^[A-Za-z0-9_-]{43}$")))
            assertFalse(json.has("attachment_crypto_id"))
        } finally {
            key.fill(0)
        }
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

    private suspend fun invokeSendEncryptedMetadata(
        viewModel: ChatViewModel,
        stamp: Any,
        chatId: String = "dm_bob",
        messageId: String = "message-stale",
        metadata: String = "hello"
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
                null,
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
        publicKey = ByteArray(128),
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
        senderPublicKey = ByteArray(128) { (seed + it).toByte() }
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
