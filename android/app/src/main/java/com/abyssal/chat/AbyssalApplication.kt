package com.abyssal.chat

import android.app.Application
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import com.abyssal.chat.presentation.viewmodel.AbyssalViewModelFactory

class AbyssalApplication : Application(), ViewModelStoreOwner {
    override val viewModelStore = ViewModelStore()

    val viewModelFactory: AbyssalViewModelFactory by lazy {
        AbyssalViewModelFactory(applicationContext)
    }
}
