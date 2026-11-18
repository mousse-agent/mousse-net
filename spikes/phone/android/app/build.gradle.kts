import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// android/build.sh fills build/rust/ with the .so files and the generated bindings.
android {
    namespace = "work.mousse.netspike"
    compileSdk = 36
    // Only used to strip the Rust .so files; the NDK that built them is the one to use.
    System.getenv("ANDROID_NDK_HOME")?.let { home ->
        ndkPath = home
        val props = Properties()
        file("$home/source.properties").takeIf { it.exists() }?.inputStream()?.use { props.load(it) }
        props.getProperty("Pkg.Revision")?.let { ndkVersion = it }
    }

    defaultConfig {
        applicationId = "work.mousse.netspike"
        // Spike 4 sets these; see spikes/phone/README.md.
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets["main"].apply {
        jniLibs.srcDir("build/rust/jniLibs")
        java.srcDir("build/rust/kotlin")
        assets.srcDir("../../web")
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
