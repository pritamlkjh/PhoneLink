plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.phonelink"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.phonelink"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            val keystorePath = System.getenv("KEYSTORE_PATH")
                ?: (project.findProperty("PHONELINK_KEYSTORE_PATH") as? String)
            val ksPassword = System.getenv("KEYSTORE_PASSWORD")
                ?: (project.findProperty("PHONELINK_KEYSTORE_PASSWORD") as? String)
            val ksAlias = System.getenv("KEY_ALIAS")
                ?: (project.findProperty("PHONELINK_KEY_ALIAS") as? String)
            val ksKeyPassword = System.getenv("KEY_PASSWORD")
                ?: (project.findProperty("PHONELINK_KEY_PASSWORD") as? String)

            if (!keystorePath.isNullOrBlank() &&
                !ksPassword.isNullOrBlank() &&
                !ksAlias.isNullOrBlank() &&
                !ksKeyPassword.isNullOrBlank()
            ) {
                val keystoreFile = File(keystorePath)
                if (keystoreFile.exists()) {
                    storeFile = keystoreFile
                    storePassword = ksPassword
                    keyAlias = ksAlias
                    keyPassword = ksKeyPassword
                    enableV1Signing = true
                    enableV2Signing = true
                    enableV3Signing = true
                    enableV4Signing = false
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            val relSigning = signingConfigs.getByName("release")
            if (relSigning.storeFile != null) {
                signingConfig = relSigning
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlin:kotlin-test:1.9.24")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.json:json:20240303")
}
