#!/bin/bash
set -euo pipefail
KERNEL_DIR=$(pwd)
CLANG="neutron"
TC_DIR="$HOME/toolchains/$CLANG-clang"

AK3_URL="https://github.com/loukious/AnyKernel3.git"
AK3_BRANCH="master"
AK3_DIR="$HOME/ginkgo/anykernel"

patch_anykernel_script() {
	local anykernel_script="$AK3_DIR/anykernel.sh"
	if [ ! -f "$anykernel_script" ]; then
		echo "Warning: $anykernel_script not found, skipping patch step."
		return 0
	fi

	sed -i -E 's/\bvayu\b/ginkgo/g; s/\bbhima\b//g' "$anykernel_script"
	echo "Patched $anykernel_script (string replacements only)."
}

# Check if AK3 exist
if ! [ -d "$AK3_DIR" ]; then
	echo "$AK3_DIR not found! Cloning to $AK3_DIR..."
	if ! git clone -q --single-branch --depth 1 -b $AK3_BRANCH $AK3_URL $AK3_DIR; then
		echo "Cloning failed! Aborting..."
		exit 1
	fi
else
	echo "$AK3_DIR found! Update $AK3_DIR"
	cd $AK3_DIR
	git pull
	cd $KERNEL_DIR
fi

patch_anykernel_script

declare -A submodules
submodules=(
    ["drivers/staging/rtl8812au"]="https://github.com/Loukious/rtl8812au.git v5.6.4.2"
    ["drivers/staging/rtl8814au"]="https://github.com/Loukious/rtl8814au v5.8.5.1"
	["drivers/staging/rtl8188eus"]="https://github.com/aircrack-ng/rtl8188eus v5.3.9"
	["drivers/staging/8821au"]="https://github.com/morrownr/8821au-20210708 main"
)

# Iterate through the submodules and clone them
for path in "${!submodules[@]}"; do
    # Extract the URL and branch
    repo_info=(${submodules[$path]})
    url=${repo_info[0]}
    branch=${repo_info[1]}

    # Create the directory if it doesn't exist
    mkdir -p "$KERNEL_DIR/$(dirname "$path")"

    # Clone or update repository
    if [ -d "$KERNEL_DIR/$path/.git" ]; then
        echo "Updating $KERNEL_DIR/$path (branch: $branch)"
        git -C "$KERNEL_DIR/$path" fetch origin "$branch"
        git -C "$KERNEL_DIR/$path" checkout "$branch"
        git -C "$KERNEL_DIR/$path" pull --ff-only origin "$branch"
    elif [ -d "$KERNEL_DIR/$path" ]; then
        echo "$KERNEL_DIR/$path exists but is not a git repo, skipping."
    else
        echo "Cloning $url into $KERNEL_DIR/$path (branch: $branch)"
        git clone -b "$branch" "$url" "$KERNEL_DIR/$path"
    fi
done

echo "All submodules are ready."

if ! [ -d "$TC_DIR" ]; then
	echo "$TC_DIR not found! Setting it up..."
	mkdir -p $TC_DIR
	cd $TC_DIR
	bash <(curl -s "https://raw.githubusercontent.com/Neutron-Toolchains/antman/main/antman") -S=10032024
	bash <(curl -s "https://raw.githubusercontent.com/Neutron-Toolchains/antman/main/antman") --patch=glibc
	cd $KERNEL_DIR
else
	echo "$TC_DIR found!"
fi

DEFCONFIG="nethunter_defconfig"
ZIP_PREFIX="NetHunter"

# Check if version argument is empty
if [ -z "$1" ]; then
	echo "Version argument is empty!"
	echo "Usage: $0 [version]"
	exit 1
fi

# Setup environment
SECONDS=0 # builtin bash timer
ZIPNAME="$ZIP_PREFIX-Loukious-$1-$(date '+%Y%m%d-%H%M').zip"
MZIPNAME="$ZIP_PREFIX-Modules-$1-Loukious-$(date '+%Y%m%d-%H%M').zip"
export PROC="-j$(nproc)"

echo "Building kernel with DEFCONFIG: $DEFCONFIG"

# Setup ccache environment
export USE_CCACHE=1
export CCACHE_EXEC=/usr/local/bin/ccache
CROSS_COMPILE+="ccache clang"

# Toolchain environtment
export PATH="$TC_DIR/bin:$PATH"
export KBUILD_COMPILER_STRING="$($TC_DIR/bin/clang --version | head -n 1 | perl -pe 's/\((?:http|git).*?\)//gs' | sed -e 's/  */ /g' -e 's/[[:space:]]*$//' -e 's/^.*clang/clang/')"
export STRIP="$TC_DIR/bin/$(echo "$(find "$TC_DIR/bin" -type f -name "aarch64-*-gcc")" | awk -F '/' '{print $NF}' | sed -e 's/gcc/strip/')"

# Kernel Details
KERNEL_VER="$(date '+%Y%m%d-%H%M')"
OUT="$HOME/ginkgo/kernel-out"

MAKE_PARAMS=(
    O="$OUT"
    ARCH=arm64
    CLANG_PATH="$TC_DIR/bin"
    CC="ccache clang"
    CXX="ccache clang++"
    HOSTCC="ccache clang"
    HOSTCXX="ccache clang++"
    LD=ld.lld
    AR=llvm-ar
    AS=llvm-as
    NM=llvm-nm
    OBJCOPY=llvm-objcopy
    OBJDUMP=llvm-objdump
    STRIP=llvm-strip
    CROSS_COMPILE="aarch64-linux-gnu-"
    CROSS_COMPILE_COMPAT="arm-linux-gnueabi-"
    CROSS_COMPILE_ARM32="arm-linux-gnueabi-"
    KBUILD_BUILD_USER="Loukious"
    KBUILD_BUILD_HOST="github"
)

function clean_all {
	cd $KERNEL_DIR
	echo
	rm -rf prebuilt
	rm -rf out && rm -rf $OUT
}

clean_all
echo
echo "All Cleaned now."

function create_modules_zip {
	if [ ! -d "${KERNEL_DIR}/modules/system/lib/modules" ]; then
		mkdir -p "${KERNEL_DIR}/modules/system/lib/modules"
	fi
    find "${KERNEL_DIR}/out/modules" -type f -iname '*.ko' -exec cp {} "${KERNEL_DIR}/modules/system/lib/modules/" \;
    cd "${KERNEL_DIR}/modules" || exit 1
    zip -r9 "../$MZIPNAME" . -x ".git*" "README.md" "LICENSE" "*.zip"
    echo -e "\n\e[1;32m[✓] Built Modules and packaged into $MZIPNAME! \e[0m"
}

# Make out folder
mkdir -p $HOME/ginkgo/kernel-out
make $PROC "${MAKE_PARAMS[@]}" $DEFCONFIG
echo -e "\nStarting compilation...\n"
make $PROC "${MAKE_PARAMS[@]}"
make $PROC "${MAKE_PARAMS[@]}" modules_install INSTALL_MOD_PATH="${KERNEL_DIR}/out/modules"
echo -e "\nBuilt RTL module files in install path:"
find "${KERNEL_DIR}/out/modules" -type f -name '*.ko' | grep -E '(88XXau|8188eu|8821au|8811au|8814au|can)' || true
if [ ! -d "${KERNEL_DIR}/modules" ]; then
	echo -e "\n\e[1;93m[*] Cloning modules repository! \e[0m"
	git clone --depth=1 https://github.com/neternels/neternels-modules "${KERNEL_DIR}/modules"
fi
create_modules_zip

# Creating zip flashable file
function create_zip {
	#Copy AK3 to out/Anykernel3
	cd $KERNEL_DIR
	cp -r $AK3_DIR AnyKernel3
	cp $OUT/arch/arm64/boot/Image AnyKernel3

	# Change dir to AK3 to make zip kernel
	cd AnyKernel3
	zip -r9 "../$ZIPNAME" * -x '*.git*' README.md *placeholder

	#Back to out folder and clean
	cd ..
	rm -rf AnyKernel3
	rm -rf $OUT/arch/arm64/boot ##keep boot to compile rom
	echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s) !"
	echo "Zip: $ZIPNAME"
}


if [ -f "$OUT/arch/arm64/boot/Image" ]; then
	echo -e "\nKernel compiled succesfully!\n"
	create_zip
	echo -e "\nDone !"
else
	echo -e "\nFailed!"
fi
