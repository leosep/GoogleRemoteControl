plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "com.leosep.googleremotecontrol"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.leosep.googleremotecontrol"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "1.1"
        resourceConfigurations += listOf("en")
    }
    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    packaging { resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "META-INF/versions/**", "META-INF/MANIFEST.MF") }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78")
}
