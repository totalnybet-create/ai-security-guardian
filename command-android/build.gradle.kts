import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "pl.siedlar.securityguardian.command.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":command-core"))
    implementation(project(":core-security"))
    implementation(project(":app-inspector"))
    implementation(project(":privacy-guard"))
    implementation(project(":network-guard"))
    implementation(project(":url-guard-core"))
    implementation(project(":audit-log"))
    implementation(project(":notifications"))
}
