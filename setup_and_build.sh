#!/bin/bash
# Exit immediately if any command fails
set -e

echo "=========================================================="
echo "Initializing Mirage Chat local headless build environment"
echo "=========================================================="

WORKSPACE_DIR="/media/n_emperor/Aadhish/Projects/Abyssal"
SDK_DIR="$WORKSPACE_DIR/android-sdk"
GRADLE_TEMP_DIR="$WORKSPACE_DIR/gradle-temp"
OUTPUT_DIR="$WORKSPACE_DIR/build-outputs"

cd "$WORKSPACE_DIR"

# 1. Download Android Command Line Tools
if [ ! -d "$SDK_DIR/cmdline-tools/latest" ]; then
    echo "[+] Downloading Android Command Line Tools..."
    curl -L -o cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip
    
    echo "[+] Extracting Android Command Line Tools..."
    mkdir -p "$SDK_DIR/cmdline-tools/latest"
    unzip -q cmdline-tools.zip
    mv cmdline-tools/* "$SDK_DIR/cmdline-tools/latest/"
    rm -rf cmdline-tools cmdline-tools.zip
    echo "[+] Command Line Tools setup complete."
else
    echo "[*] Android Command Line Tools already exists. Skipping download."
fi

# 2. Download Temporary Gradle for Wrapper generation
if [ ! -d "$GRADLE_TEMP_DIR/gradle-8.7" ]; then
    echo "[+] Downloading temporary Gradle 8.7..."
    curl -L -o gradle.zip https://services.gradle.org/distributions/gradle-8.7-bin.zip
    
    echo "[+] Extracting Gradle..."
    mkdir -p "$GRADLE_TEMP_DIR"
    unzip -q gradle.zip -d "$GRADLE_TEMP_DIR"
    rm gradle.zip
    echo "[+] Gradle extraction complete."
else
    echo "[*] Gradle already exists. Skipping download."
fi

# 3. Generate the standard gradle wrapper files
if [ ! -f "android/gradlew" ]; then
    echo "[+] Generating Gradle Wrapper in android/ directory..."
    cd android
    "$GRADLE_TEMP_DIR/gradle-8.7/bin/gradle" wrapper --gradle-version 8.7 --distribution-type bin
    cd ..
    echo "[+] Gradle Wrapper created."
else
    echo "[*] Gradle Wrapper already exists."
fi

# 4. Configure local.properties pointing to our local SDK
echo "[+] Configuring android/local.properties..."
echo "sdk.dir=$SDK_DIR" > android/local.properties

# 5. Pre-accept SDK licenses and download platform components
echo "[+] Auto-accepting Android SDK licenses..."
yes | "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" --licenses

echo "[+] Downloading Android SDK components (platforms;android-34, build-tools;34.0.0, platform-tools)..."
"$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" "platforms;android-34" "build-tools;34.0.0" "platform-tools"

# 6. Execute Gradle build of the APK
echo "[+] Running Gradle build (assembleDebug)..."
cd android
chmod +x gradlew
./gradlew assembleDebug

# 7. Copy compiled APK to the local workspace build-outputs/ directory
echo "[+] Staging compiled debug APK..."
mkdir -p "$OUTPUT_DIR"
cp app/build/outputs/apk/debug/app-debug.apk "$OUTPUT_DIR/mirage-chat-debug.apk"

echo "=========================================================="
echo "BUILD SUCCESSFUL!"
echo "APK Location: $OUTPUT_DIR/mirage-chat-debug.apk"
echo "=========================================================="
