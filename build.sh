#!/usr/bin/env bash
# Manual APK build for NetAver DNS Kotlin rewrite (no Gradle): aapt2 + kotlinc + d8 + apksigner
set -euo pipefail

APP=~/workspace/netaver-dns-kotlin/app
OUT=~/workspace/netaver-dns-kotlin/out
SRC=$APP/kotlin-src
SDK=~/android-sdk
BT=$SDK/build-tools/34.0.0
AJAR=$SDK/platforms/android-34/android.jar
KOTLINC=~/kotlin/kotlinc/bin/kotlinc
STDLIB=~/kotlin/kotlinc/lib/kotlin-stdlib.jar
KS=$APP/../debug.keystore
APKNAME="NetAverDNS-v2.2.13.apk"
EXPECT_CERT="57b11da5b0502c7e64f15961999b152e0203c3447ab1342b3008ecccf44e592e"

export JAVA_HOME=~/jdk17
export PATH=$JAVA_HOME/bin:$PATH

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
# NOTE: keystore lives OUTSIDE $OUT on purpose (same as Java project):
# build.sh wipes $OUT every run, a fresh key each build would break install-over.
$BT/apksigner sign --ks "$KS" \
  --ks-pass pass:android --key-pass pass:android \
  --out "$OUT/$APKNAME" "$OUT/app-aligned.apk"

echo "== verify cert =="
ACTUAL=$($BT/apksigner verify --print-certs "$OUT/$APKNAME" | grep -i "SHA-256" | head -1 | awk '{print $NF}' | tr 'A-Z' 'a-z')
echo "cert SHA-256: $ACTUAL"
if [ "$ACTUAL" != "$EXPECT_CERT" ]; then
  echo "CERT MISMATCH! Expected $EXPECT_CERT"
  exit 1
fi

ls -la "$OUT/$APKNAME"
echo "BUILD OK"
