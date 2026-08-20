plugins {
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":command-core"))
    testImplementation(kotlin("test-junit"))
}

tasks.test {
    useJUnit()
}
