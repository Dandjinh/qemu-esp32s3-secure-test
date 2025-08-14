#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

EFUSE_FILE_PATH="$SCRIPT_DIR/efuse.bin"
AES_KEY_PATH="$SCRIPT_DIR/aes-key.bin"
RSA_KEY_PATH="$SCRIPT_DIR/rsa-key.pem"
DIGEST_PATH="$SCRIPT_DIR/digest.bin"
FLASH_PATH="$SCRIPT_DIR/flash.bin"

FW_PACK_PATH=build/pack
FW_FILES=(
    "0x0:bootloader.bin"
    "0x10000:partition-table.bin"
    "0x13000:ota_data_initial.bin"
    "0x20000:secure_test.bin"
)

enable_flash_encryption()
{
    local use_large_key=1
    local key_size=0

    # rm key if size not match
    if [[ -f $AES_KEY_PATH ]]; then
        key_size=$(ls -all $AES_KEY_PATH | awk '{print $5;}')
        if [[ ($use_large_key -eq 1) && ($key_size -ne 64) ]]; then
            rm $AES_KEY_PATH
        elif [[ ($use_large_key -eq 0) && ($key_size -ne 32) ]]; then
            rm $AES_KEY_PATH
        fi
    fi

    # generate an aes key if not exist
    if [[ ! -f $AES_KEY_PATH ]]; then
        echo "@@@ generate aes-key file"
        if [[ $use_large_key -eq 1 ]]; then
            espsecure.py generate_flash_encryption_key \
                --keylen 512 $AES_KEY_PATH \
                >/dev/null
            key_size=64
        else
            espsecure.py generate_flash_encryption_key \
                $AES_KEY_PATH \
                >/dev/null
            key_size=32
        fi
    fi

    # burn the aes key into efuse
    echo "@@@ burn aes-key, ${key_size}"
    if [[ $use_large_key -eq 1 ]]; then
        idf.py qemu --efuse-file $EFUSE_FILE_PATH \
            efuse-burn-key --do-not-confirm BLOCK_KEY1 $AES_KEY_PATH XTS_AES_256_KEY \
            >/dev/null
    else
        idf.py qemu --efuse-file $EFUSE_FILE_PATH \
            efuse-burn-key --do-not-confirm BLOCK_KEY1 $AES_KEY_PATH XTS_AES_128_KEY \
            >/dev/null
    fi

    # enable flash encryption
    echo "@@@ enable flash encryption"
    idf.py qemu --efuse-file $EFUSE_FILE_PATH \
        efuse-burn --do-not-confirm SPI_BOOT_CRYPT_CNT 1 \
        >/dev/null
}

encrypt_files()
{
    # create an empty file and fill it with 0xFF
    dd if=/dev/zero bs=1M count=4 | tr '\000' '\377' > "$FLASH_PATH"

    for item in "${FW_FILES[@]}"; do
        IFS=':' read -r addr file <<< "$item"

        local src_file="$FW_PACK_PATH/$file"
        local encrypted_file="$SCRIPT_DIR/tmp/$file"

        echo "@@@ encrypting $src_file (addr: $addr)"

        # encrypt file
        espsecure.py encrypt_flash_data \
            --aes_xts --keyfile "$AES_KEY_PATH" \
            --address "$addr" --output "$encrypted_file" \
            "$src_file" \
            >/dev/null

        # copy encrypted file into flash file
        dd if="$encrypted_file" of="$FLASH_PATH" \
           bs=1 seek=$((addr)) conv=notrunc status=none \
           >/dev/null
    done
}

enable_secure_boot_v2()
{
    # create rsa key if not exist
    if [[ ! -f "$DIGEST_PATH" ]]; then
        echo "@@@ generate rsa-key file"
        espsecure.py generate_signing_key --version 2 --scheme rsa3072 $RSA_KEY_PATH
        espsecure.py digest_sbv2_public_key --keyfile $RSA_KEY_PATH --output $DIGEST_PATH
    fi

    # burn the digest data into efuse
    echo "@@@ burn rsa digest"
    idf.py qemu --efuse-file $EFUSE_FILE_PATH \
        efuse-burn-key --do-not-confirm BLOCK_KEY3 $DIGEST_PATH SECURE_BOOT_DIGEST0 \
        >/dev/null

    # enable secure boot
    echo "@@@ enable secure boot"
    idf.py qemu --efuse-file $EFUSE_FILE_PATH \
        efuse-burn --do-not-confirm SECURE_BOOT_EN \
        >/dev/null
}

burn_efuse()
{
    local values=(
        DIS_DOWNLOAD_ICACHE
        DIS_DOWNLOAD_DCACHE
        HARD_DIS_JTAG
        SOFT_DIS_JTAG
        DIS_DIRECT_BOOT
        DIS_USB_JTAG
        DIS_DOWNLOAD_MANUAL_ENCRYPT
    )

    for val in "${values[@]}"; do
        echo "@@@ burn-efuse ${val}"
        idf.py qemu --efuse-file $EFUSE_FILE_PATH \
            efuse-burn --do-not-confirm $val 0x1 \
            >/dev/null
    done
}

start()
{
    # start qemu with specific efuse and flash file
    idf.py qemu \
        --efuse-file $EFUSE_FILE_PATH \
        --flash-file $FLASH_PATH \
        monitor
}

select_qemu()
{
    # local target_version="9.0.0"
    local target_version="9.2.2"

    # check qemu version
    local qemu_version=$(qemu-system-xtensa --version | head -n 1 | awk '{print $4;}')
    if [[ "$qemu_version" != "$target_version" ]]; then
        local qemu_path=$(which qemu-system-xtensa)
        local target_path=$qemu_path
        # qemu_path="/path/tools/qemu-xtensa/esp_develop_9.0.0_20240606/qemu/bin/qemu-system-xtensa"

        local current_dir=$(dirname "$qemu_path")
        while [[ "$current_dir" != "/" ]]; do
            local current_name=$(basename "$current_dir")
            local parent_dir=$(dirname "$current_dir")
            local parent_name=$(basename "$parent_dir")

            if [[ "$parent_name" == "qemu-xtensa" ]]; then
                if [[ ! -L "$current_dir" ]]; then
                    # backup origin folder
                    echo "$current_dir" >> "$SCRIPT_DIR/exec/backup.txt"
                    cp -r "$current_dir" "$SCRIPT_DIR/exec/${current_name}-bak"
                fi
                rm -rf "$current_dir"
                ln -sf "$SCRIPT_DIR/exec/bin$target_version" "$current_dir"
                break
            fi

            current_dir="$parent_dir"
        done
    fi

    echo "@@@ qemu version"
    qemu-system-xtensa --version
}

if [[ -f $EFUSE_FILE_PATH ]]; then
    rm $EFUSE_FILE_PATH
fi

select_qemu
enable_flash_encryption
encrypt_files
enable_secure_boot_v2
# burn_efuse
start
