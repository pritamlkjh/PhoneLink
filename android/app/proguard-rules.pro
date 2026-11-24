# PhoneLink R8 / ProGuard Configuration Rules

# 1. Android Platform & Lifecycle Components
-keep public class * extends android.app.Service { *; }
-keep public class * extends android.content.BroadcastReceiver { *; }
-keep public class * extends android.app.Activity { *; }
-keep public class * extends android.app.Application { *; }

# 2. Cryptographic & Security Boundaries
# Preserves KeyStore reflection helpers used in AndroidKeyStoreSigner
-keep class android.security.keystore.** { *; }
-dontwarn android.security.keystore.**
-keep class java.security.** { *; }
-keep class javax.crypto.** { *; }
-keep class com.phonelink.crypto.** { *; }

# 3. Protocol & Service Models (JSON / Binary serialization)
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keep class com.phonelink.service.ConnectionForegroundService { *; }
-keep class com.phonelink.receiver.BootReceiver { *; }
-keep class com.phonelink.camera.** { *; }
-keep class com.phonelink.files.** { *; }
-keep class com.phonelink.actions.** { *; }
-keep class com.phonelink.storage.** { *; }
-keep class com.phonelink.transport.** { *; }
-keep class com.phonelink.identity.** { *; }

# 4. OkHttp & Networking
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase
-dontwarn org.codehaus.mojo.animal_sniffer.*

# 5. Kotlin Metadata & Coroutines
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature, SourceFile, LineNumberTable
-dontwarn kotlin.**
-keepclassmembers class * {
    @kotlin.jvm.JvmField <fields>;
}
