package com.abyssal.chat.domain.model

private val GENERATED_ACCOUNT = Regex("^acct_([0-9a-fA-F]{8,})$")

/** Shortens a generated account ID such as `acct_10ba…ce30` to `10ba…ce30`, like the web client. */
fun shortAccountId(username: String): String {
    val hex = GENERATED_ACCOUNT.matchEntire(username)?.groupValues?.get(1) ?: return username
    return "${hex.take(4)}…${hex.takeLast(4)}"
}
