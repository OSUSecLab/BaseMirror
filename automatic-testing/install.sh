#!/usr/bin/env bash

#adb push ~/Desktop/5G/frida-android-hooks/frida-inject /data/local/tmp
#adb push ~/Desktop/5G/frida-android-hooks/frida-server /data/local/tmp
#adb shell "su -c chmod 755 /data/local/tmp/frida-inject"
#adb shell "su -c chmod 755 /data/local/tmp/frida-server"

adb push ./scripts/native.js /data/local/tmp
adb push ./scripts/cbd.js /data/local/tmp
adb push ./scripts/init.js /data/local/tmp

adb push ./frida-auto-hook.sh /data/local/tmp
adb shell "su -c mv /data/local/tmp/frida-auto-hook.sh /data/adb/post-fs-data.d/"
adb shell "su -c chmod +x /data/adb/post-fs-data.d/frida-auto-hook.sh"
adb shell "su -c chown root /data/adb/post-fs-data.d/frida-auto-hook.sh"

aarch64-linux-android23-clang -fPIE -pie -ldl -o test_cmd{,.c}
adb push ./test_cmd /data/local/tmp
adb shell "su -c chmod +x /data/local/tmp/test_cmd"

# wget https://github.com/frida/frida/releases/download/16.2.1/frida-server-16.2.1-android-arm64.xz
# xz -d frida-server-16.2.1-android-arm64.xz
adb push ./frida-server-16.2.1-android-arm64 /data/local/tmp
adb shell "su -c chmod +x /data/local/tmp/frida-server-16.2.1-android-arm64"

mkdir raw_logs
mkdir cmds_logs