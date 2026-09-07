package com.abyssal.chat.domain.model

import java.util.UUID

object RoomIdentifiers {
    fun newForumId(): String = "forum_" + UUID.randomUUID().toString().replace("-", "")
}
