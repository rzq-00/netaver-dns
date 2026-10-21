#!/usr/bin/env bash
# Manual APK build for NetAver DNS (no Gradle): aapt2 + kotlinc + d8 + apksigner
#
# Toolchain (override via environment):
#   JDK_HOME      default ~/jdk17
#   KOTLINC_HOME  default ~/kotlin/kotlinc
#   SDK_HOME      default ~/android-sdk   (platform android-34, build-tools 34.0.0)
# Signing:
#   Uses ./debug.keystore (git-ignored — create your own, see README).
#   Set EXPECT_CERT to your keystore's SHA-256 fingerprint to pin it;
#   leave it empty to skip the pin check (a warning is printed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/app"
OUT="$ROOT/out"
SRC="$APP/kotlin-src"
JDK_HOME="${JDK_HOME:-$HOME/jdk17}"
KOTLINC_HOME="${KOTLINC_HOME:-$HOME/kotlin/kotlinc}"
SDK_HOME="${SDK_HOME:-$HOME/android-sdk}"
BT="$SDK_HOME/build-tools/34.0.0"
AJAR="$SDK_HOME/platforms/android-34/android.jar"
KOTLINC="$KOTLINC_HOME/bin/kotlinc"
STDLIB="$KOTLINC_HOME/lib/kotlin-stdlib.jar"
KS="$ROOT/debug.keystore"
APKNAME="NetAverDNS-v2.2.12.apk"
EXPECT_CERT="${EXPECT_CERT:-}"

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

if [ ! -f "$KS" ]; then
  echo "Missing $KS — create your own signing keystore first (see README, 'Building from source')."
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT/compiled_res" "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "== aapt2 compile =="
$BT/aapt2 compile --dir "$APP/res" -o "$OUT/compiled_res.zip"

echo "== aapt2 link =="
$BT/aapt2 link -o "$OUT/app-unsigned.apk" \
  -I "$AJAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --min-sdk-version 29 --target-sdk-version 34 \
  --java "$OUT/gen" \
  -A "$APP/assets" \
  "$OUT/compiled_res.zip"

echo "== javac (R.java only) =="
javac -source 8 -target 8 -nowarn -encoding UTF-8 \
  -classpath "$AJAR" \
  -d "$OUT/classes" \
  $(find "$OUT/gen" -name "*.java")

echo "== kotlinc =="
find "$SRC" -name "*.kt" > "$OUT/sources.txt"
wc -l < "$OUT/sources.txt"
set +e
$KOTLINC -jvm-target 1.8 -no-stdlib -nowarn \
  -classpath "$AJAR:$OUT/classes:$STDLIB" \
  -d "$OUT/classes" \
  @"$OUT/sources.txt" > "$OUT/kotlinc.log" 2>&1
KOTLINC_RC=$?
set -e
grep -v "^warning:" "$OUT/kotlinc.log" | head -40 || true
if [ $KOTLINC_RC -ne 0 ]; then
  echo "KOTLINC FAILED (rc=$KOTLINC_RC)"
  exit 1
fi
if [ -z "$(find "$OUT/classes/com" -name '*.class' 2>/dev/null | head -1)" ]; then
  echo "KOTLINC produced no app classes"
  exit 1
fi

echo "== d8 =="
$BT/d8 --min-api 29 --lib "$AJAR" \
  --output "$OUT/dex" \
  $(find "$OUT/classes" -name "*.class" | tr '\n' ' ') \
  "$STDLIB"

echo "== add dex to apk =="
python3 - "$OUT/app-unsigned.apk" "$OUT/dex/classes.dex" << 'EOF'
import sys, zipfile
apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, 'a', zipfile.ZIP_DEFLATED) as z:
    z.write(dex, 'classes.dex')
print("dex added")
EOF

echo "== zipalign =="
$BT/zipalign -f 4 "$OUT/app-unsigned.apk" "$OUT/app-aligned.apk"

echo "== apksigner =="
# NOTE: keystore lives OUTSIDE $OUT on purpose:
# build.sh wipes $OUT every run; a fresh key each build would break install-over.
$BT/apksigner sign --ks "$KS" \
  --ks-pass pass:android --key-pass pass:android \
  --out "$OUT/$APKNAME" "$OUT/app-aligned.apk"

echo "== verify cert =="
ACTUAL=$($BT/apksigner verify --print-certs "$OUT/$APKNAME" | grep -i "SHA-256" | head -1 | awk '{print $NF}' | tr 'A-Z' 'a-z')
echo "cert SHA-256: $ACTUAL"
if [ -n "$EXPECT_CERT" ] && [ "$ACTUAL" != "$EXPECT_CERT" ]; then
  echo "CERT MISMATCH! Expected $EXPECT_CERT"
  exit 1
fi
if [ -z "$EXPECT_CERT" ]; then
  echo "(EXPECT_CERT not set — pin check skipped. Set it to lock the build to your key.)"
fi

ls -la "$OUT/$APKNAME"
echo "BUILD OK"
