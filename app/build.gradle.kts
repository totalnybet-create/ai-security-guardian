plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "pl.siedlar.securityguardian"
    compileSdk = 36

    defaultConfig {
        applicationId = "pl.siedlar.securityguardian"
        minSdk = 23
        targetSdk = 36
        versionCode = 7
        versionName = "0.6.0-p5-lock"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    implementation(project(":core-security"))
    implementation(project(":app-inspector"))
    implementation(project(":audit-log"))
    implementation(project(":notifications"))
    implementation(project(":privacy-guard"))
    implementation(project(":malware-core"))
    implementation(project(":file-scanner"))
    implementation(project(":quarantine"))
    implementation(project(":install-guard"))
    implementation(project(":network-guard"))
    implementation(project(":url-guard-core"))
    implementation(project(":command-core"))
    implementation(project(":command-android"))
    implementation(project(":ai-copilot-core"))
    implementation(project(":voice-android"))

    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.13.0")

    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
