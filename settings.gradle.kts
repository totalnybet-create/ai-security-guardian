pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "AI Security Guardian"

include(
    ":app",
    ":core-security",
    ":app-inspector",
    ":privacy-guard",
    ":malware-core",
    ":file-scanner",
    ":quarantine",
    ":install-guard",
    ":audit-log",
    ":notifications",
)
