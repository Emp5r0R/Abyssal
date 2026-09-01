plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
}

val releaseStorePath = providers.environmentVariable("ABYSSAL_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("ABYSSAL_KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("ABYSSAL_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("ABYSSAL_KEY_PASSWORD").orNull
val releaseBuildId = providers.environmentVariable("ABYSSAL_BUILD_ID").orNull
    ?: "android@0.0.0"
val releaseBuildSignature = providers.environmentVariable("ABYSSAL_BUILD_SIGNATURE_B64").orNull
    ?: ""
val releaseSourceCommit = providers.environmentVariable("ABYSSAL_SOURCE_COMMIT").orNull
    ?: "0000000000000000000000000000000000000000"
val releaseBuildConfigured = releaseBuildSignature.isNotEmpty()

require(Regex("^android@(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$").matches(releaseBuildId)) {
    "ABYSSAL_BUILD_ID is invalid"
}
require(releaseBuildSignature.isEmpty() || Regex("^[A-Za-z0-9_-]{86}$").matches(releaseBuildSignature)) {
    "ABYSSAL_BUILD_SIGNATURE_B64 is invalid"
}
require(Regex("^[0-9a-f]{40}$").matches(releaseSourceCommit)) {
    "ABYSSAL_SOURCE_COMMIT is invalid"
}
val hasReleaseSigning = listOf(
    releaseStorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "com.abyssal.chat"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.abyssal.chat"
        minSdk = 26
        targetSdk = 34
        versionCode = 25
        versionName = "2.3.1"

        buildConfigField(
            "String",
            "UPDATE_API_URL",
            "\"https://api.github.com/repos/Emp5r0R/Abyssal/releases/latest\""
        )
        buildConfigField("String", "RELEASE_BUILD_ID", "\"$releaseBuildId\"")
        buildConfigField("String", "RELEASE_BUILD_SIGNATURE_B64", "\"$releaseBuildSignature\"")
        buildConfigField("String", "RELEASE_SOURCE_COMMIT", "\"$releaseSourceCommit\"")
        buildConfigField("boolean", "RELEASE_BUILD_CONFIGURED", releaseBuildConfigured.toString())

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(requireNotNull(releaseStorePath))
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                // minSdk 26 supports APK Signature Scheme v2/v3. Do not emit the
                // legacy JAR/v1 scheme, which is not needed for this application.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
                // v4 is an optional incremental-install sidecar and is not part of
                // the distributed artifact; keep release verification deterministic.
                enableV4Signing = false
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.11"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

tasks.withType<Test>().configureEach {
    systemProperty(
        "jna.library.path",
        rootProject.layout.projectDirectory.dir("../target/release").asFile.absolutePath
    )
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.okhttp)
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation("com.google.zxing:core:3.5.4")

    testImplementation(libs.junit)
    testImplementation("net.java.dev.jna:jna:5.19.1")
    testImplementation("org.json:json:20260814")
    testImplementation("com.squareup.okhttp3:mockwebserver:5.5.0")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
