package com.abyssal.chat.data.network

import org.json.JSONObject

internal object RoomProfileCodec {
    private val edgeWhitespace = Regex("^[\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]|[\\u0020\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]$")

    fun encode(name: String): JSONObject {
        require(name.length in 1..36 && !edgeWhitespace.containsMatchIn(name) && name.none(Char::isISOControl))
        require(name.codePoints().noneMatch { it in 0xd800..0xdfff })
        return JSONObject().put("version", 1).put("name", name)
    }

    fun decode(value: Any?): String {
        val profile = value as? JSONObject ?: error("Room unavailable")
        require(profile.length() == 2 && (profile.opt("version") as? Number)?.toDouble() == 1.0)
        val name = profile.opt("name") as? String ?: error("Room unavailable")
        encode(name)
        return name
    }
}
