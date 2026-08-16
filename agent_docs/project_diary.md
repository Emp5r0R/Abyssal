# Project Diary

## 2026-08-16 - V2 directory equivocation detection

The relay now emits a V2 directory checkpoint in presence. Its SHA-256 transcript includes the authenticated node ID, the monotonic append-only account-map revision, and the sorted username-to-stable-64-byte-identity map. Account-map admission and encrypted fanout share the conversation transaction lock; presence snapshot computation and serialized fanout prevent concurrent broadcasts from publishing an older checkpoint after a newer one. The relay requires the exact current checkpoint before admission. Web and Android recompute the transcript and retain up to 32 stamps in RAM. Text, attachment metadata, and read receipts bind the checkpoint in both authenticated inner payload and outer frame; conflicts, cross-node/newer/altered replay evidence, or mismatches fail closed before ACK/publication, while evicted unknown-old frames drop without decryption or ACK.

This is bounded equivocation detection, not transparency. There is no signed append-only external witness or monitor; permanently partitioned/noncommunicating clients can evade gossip; logout, restart, or RAM-only lifecycle loss clears history; and the 32-stamp cap can turn an older valid frame into an availability drop.
