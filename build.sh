#!/usr/bin/env bash

# Stop at errors
set -e

CommonCompilerFlags="-O0 -g -ggdb -fdiagnostics-color=always -std=gnu11 -fno-rtti -fno-exceptions -ffast-math -msse4.1
-Wall -Werror -Wconversion
-Wno-writable-strings -Wno-gnu-anonymous-struct
-Wno-padded -Wno-string-conversion
-Wno-error=sign-conversion -Wno-incompatible-function-pointer-types
-Wno-error=unused-variable -Wno-unused-function
-Wno-error=unused-command-line-argument"

CommonDefines="-DAPP_DEBUG=1 -DAPP_INTERNAL=1 -DOS_NAME=${OS_NAME}"

# the goal should be -nostdlib
CommonLinkerFlags="-Wl,--gc-sections -lm -lpthread -ldl"

if [ -z "$1" ]; then
    OS_NAME=$(uname -o 2>/dev/null || uname -s)
else
    OS_NAME="$1"
fi

echo "Building for $OS_NAME..."

curDir=$(pwd)
srcDir="$curDir"
buildDir="$curDir/build"

[ -d $buildDir ] || mkdir -p $buildDir

pushd $buildDir > /dev/null

# NOTE(dgl): currently only x64 code. For other architectures we have to adjust the intrinsics.
if [ "$OS_NAME" == "GNU/Linux" ] || [ "$OS_NAME" == "Linux" ]; then
    clang -fPIC $CommonCompilerFlags $CommonDefines $CommonLinkerFlags -o linux_main_x64 $srcDir/main.c
else
    echo "$OS_NAME is currently not supported"
fi

popd > /dev/null
