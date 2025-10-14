#!/bin/bash

VMDIR=$1
IMAGE_PATH=./images/$(jq -r '.image' ${VMDIR}/vm-manifest.json)
IMG_METADATA=${IMAGE_PATH}/metadata.json
MEM=$(jq -r '.memory' ${VMDIR}/vm-manifest.json)
VCPUS=$(jq -r '.vcpu' ${VMDIR}/vm-manifest.json)

VDA=${VMDIR}/hda.img

PROCESS_NAME=csv-vm

INITRD=${IMAGE_PATH}/$(jq -r '.initrd' ${IMG_METADATA})
KERNEL=${IMAGE_PATH}/$(jq -r '.kernel' ${IMG_METADATA})
CDROM=${IMAGE_PATH}/$(jq -r '.rootfs' ${IMG_METADATA})
CSV_FIRMWARE=${IMAGE_PATH}/$(jq -r '.bios' ${IMG_METADATA})
CMDLINE=$(jq -r '.cmdline' ${IMG_METADATA})
CONFIG_DIR=${VMDIR}/shared
CSV=${CSV:-1}
#CSV=${CSV:0}  # 设置 CSV 为 0，表示不使用 CSV
RO=${RO:-on}

ARGS="${ARGS} -kernel ${KERNEL}"
ARGS="${ARGS} -initrd ${INITRD}"

echo INITRD=${INITRD}
echo ARGS=${ARGS}
echo VDA=${VDA}
echo CMDLINE=${CMDLINE}
echo CSV=${CSV}

if [ "${CSV}" == "1" ]; then
	MACHINE_ARGS=",memory-encryption=sev0"
	PROCESS_NAME=csv-vm
	# CSV/SEV 参数配置
	CSV_ARGS="-object sev-guest,id=sev0,policy=0x1,cbitpos=47,reduced-phys-bits=5"
fi
BIOS="-bios ${CSV_FIRMWARE}"

sleep 2

qemu-system-x86_64 \
		   --enable-kvm \
		   -cpu host \
		   -m ${MEM}M -smp ${VCPUS} \
		   -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
		   -machine q35,kernel_irqchip=split${MACHINE_ARGS} \
		   ${BIOS} \
		   ${CSV_ARGS} \
		   -nographic \
		   -nodefaults \
		   -chardev stdio,id=ser0,signal=on -serial chardev:ser0 \
		   -device virtio-net-pci,netdev=nic0_td -netdev user,id=nic0_td \
		   -drive file=${VDA},if=none,id=virtio-disk0 -device virtio-blk-pci,drive=virtio-disk0 \
		   -cdrom ${CDROM} \
		   -virtfs local,path=${CONFIG_DIR},mount_tag=host-shared,readonly=${RO},security_model=mapped,id=virtfs0 \
		   ${ARGS} \
		   -append "${CMDLINE}"
