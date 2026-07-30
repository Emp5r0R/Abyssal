# App-specific R8 rules belong here when reflection or JNI integrations require them.
-keep class uniffi.abyssal_core.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**
