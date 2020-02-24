#!/usr/bin/env bash
# based on: https://wiki.debian.org/RaspberryPi/qemu-user-static
# and https://z4ziggy.wordpress.com/2015/05/04/from-bochs-to-chroot/
#
# and pwnagotchi's old create_sibling script:
# https://raw.githubusercontent.com/evilsocket/pwnagotchi/55bac8a8b913c158132953d8186d278621df032a/scripts/create_sibling.sh

set -eu

if [[ "$EUID" -ne 0 ]]; then
   echo "Run this script as root!"
   exit 1
fi

REQUIREMENTS=( wget gunzip git dd e2fsck resize2fs parted losetup qemu-system-x86_64 )
DEBREQUIREMENTS=( wget gzip git parted qemu-system-x86 qemu-user-static )
REPO_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
TMP_DIR="${REPO_DIR}/tmp"
MNT_DIR="${TMP_DIR}/mnt"
THIS_DIR=$(pwd)

HOST_NAME="pisniffer"
OUTPUT_NAME="pi_sniffer.img"
IMAGE_SIZE="7"

function check_dependencies() {
  if [ -f /etc/debian_version ];
  then
    echo "[+] Checking Debian dependencies"

    for REQ in "${DEBREQUIREMENTS[@]}"; do
      if ! dpkg -s "$REQ" >/dev/null 2>&1; then
        echo "Dependency check failed for ${REQ}; use 'apt install ${REQ}' to install"
        exit 1
      fi
    done
  fi

  echo "[+] Checking dependencies"
  for REQ in "${REQUIREMENTS[@]}"; do
    if ! type "$REQ" >/dev/null 2>&1; then
      echo "Dependency check failed for ${REQ}"
      exit 1
    fi
  done

  if ! test -e /usr/bin/qemu-arm-static; then
    echo "[-] You need the package \"qemu-user-static\" for this to work."
    exit 1
  fi

  if ! systemctl is-active systemd-binfmt.service >/dev/null 2>&1; then
     mkdir -p "/lib/binfmt.d"
     echo ':qemu-arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:F' > /lib/binfmt.d/qemu-arm-static.conf
     systemctl restart systemd-binfmt.service
  fi
}

function get_raspbian() {
  URL="https://downloads.raspberrypi.org/raspbian_lite_latest"
  echo "[+] Downloading raspbian lite latest to raspbian.zip"
  mkdir -p "${TMP_DIR}"
  wget --show-progress -qcO "${TMP_DIR}/raspbian.zip" "$URL"
  echo "[+] Unpacking raspbian.zip to raspbian.img"
  gunzip -c "${TMP_DIR}/raspbian.zip" > "${TMP_DIR}/raspbian.img"
}

function setup_raspbian(){
  # Note that we 'extend' the raspbian.img
  echo "[+] Resizing full image to ${IMAGE_SIZE}G"

  # Full disk-space using image (appends to raspbian image)
  dd if=/dev/zero bs=1G count="${IMAGE_SIZE}" >> "${TMP_DIR}/raspbian.img"
  truncate --size="${IMAGE_SIZE}"G "${TMP_DIR}/raspbian.img"

  echo "[+] Setup loop device"
  mkdir -p "${MNT_DIR}"
  LOOP_PATH="$(losetup --find --partscan --show "${TMP_DIR}/raspbian.img")"
  PART2_START="$(parted -s "$LOOP_PATH" -- print | awk '$1==2{ print $2 }')"
  parted -s "$LOOP_PATH" rm 2
  parted -s "$LOOP_PATH" mkpart primary "$PART2_START" 100%
  echo "[+] Check FS"
  e2fsck -y -f "${LOOP_PATH}p2"
  echo "[+] Resize FS"
  resize2fs "${LOOP_PATH}p2"
  echo "[+] Device is ${LOOP_PATH}"
  echo "[+] Unmount if already mounted with other img"
  mountpoint -q "${MNT_DIR}" && umount -R "${MNT_DIR}"
  echo "[+] Mount /"
  mount -o rw "${LOOP_PATH}p2" "${MNT_DIR}"
  echo "[+] Mount /boot"
  mount -o rw "${LOOP_PATH}p1" "${MNT_DIR}/boot"
  mount --bind /dev "${MNT_DIR}/dev/"
  mount --bind /sys "${MNT_DIR}/sys/"
  mount --bind /proc "${MNT_DIR}/proc/"
  mount --bind /dev/pts "${MNT_DIR}/dev/pts"
  cp /usr/bin/qemu-arm-static "${MNT_DIR}/usr/bin"
  cp /etc/resolv.conf "${MNT_DIR}/etc/resolv.conf"
}

function provision_raspbian() {

  # copy in pi sniffer
  cd ${MNT_DIR}/home/pi/
  cp -r ${REPO_DIR}/pi_sniffer .
  cp ${REPO_DIR}/ui/* .
  cp ${REPO_DIR}/configs/rc.local ../../etc/
  chmod +x /etc/rc.local
  cp ${REPO_DIR}/configs/kismet.conf .
  cp ${REPO_DIR}/configs/ntp.conf ../../etc/

  cd ${MNT_DIR}
  sed -i'' 's/^\([^#]\)/#\1/g' etc/ld.so.preload # add comments
  echo "[+] Run chroot commands"
  LANG=C LC_ALL=C LC_CTYPE=C chroot . bin/bash -x <<EOF
  set -eu
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  uname -a

  apt -y update
  apt -y upgrade
  apt -y install git build-essential python3-pip tcpdump
  apt -y install libpcap-dev cmake gpsd gpsd-clients
  apt -y install aircrack-ng kismet libtins-dev libpugixml-dev
  apt -y install libssl-dev python3-pil python-smbus i2c-tools python-gi 
  apt -y install libboost-all-dev 
  apt -y install ntp

  # setup dphys-swapfile
  echo "CONF_SWAPSIZE=1024" >/etc/dphys-swapfile
  systemctl enable dphys-swapfile.service

  # compile pi sniffer
  cd home/pi/pi_sniffer
  mkdir build
  cd build
  cmake ..
  make

  cd /

  # configure pwnagotchi
  echo -e "$HOST_NAME" > /etc/hostname
  sed -i "s@^127\.0\.0\.1 .*@127.0.0.1 localhost "$HOST_NAME" "$HOST_NAME".local@g" /etc/hosts

  # interface dependencies
  pip3 install adafruit-circuitpython-ssd1306 spidev RPI.GPIO adafruit-blinka

  echo "dtparam=i2c_arm=on" >> boot/config.txt
  echo "dtparam=spi=on" >> boot/config.txt
  echo "i2c-dev" >> etc/modules
  echo "hi" >> boot/ssh

  # Re4son-Kernel
  echo "deb http://http.re4son-kernel.com/re4son/ kali-pi main" > /etc/apt/sources.list.d/re4son.list
  wget -O - https://re4son-kernel.com/keys/http/archive-key.asc | apt-key add -
  apt update
  apt install -y kalipi-kernel kalipi-bootloader kalipi-re4son-firmware kalipi-kernel-headers libraspberrypi0 libraspberrypi-dev libraspberrypi-doc libraspberrypi-bin

  # Fix PARTUUID
  PUUID_ROOT="\$(blkid "\$(df / --output=source | tail -1)" | grep -Po 'PARTUUID="\K[^"]+')"
  PUUID_BOOT="\$(blkid "\$(df /boot --output=source | tail -1)" | grep -Po 'PARTUUID="\K[^"]+')"

  # sed regex info: search for line containing / followed by whitespace or /boot (second sed)
  #                 in this line, search for PARTUUID= followed by letters, numbers or "-"
  #                 replace that match with the new PARTUUID
  sed -i "/\/[ ]\+/s/PARTUUID=[A-Za-z0-9-]\+/PARTUUID=\$PUUID_ROOT/g" /etc/fstab
  sed -i "/\/boot/s/PARTUUID=[A-Za-z0-9-]\+/PARTUUID=\$PUUID_BOOT/g" /etc/fstab

  sed -i "s/root=[^ ]\+/root=PARTUUID=\${PUUID_ROOT}/g" /boot/cmdline.txt

  # delete keys
  find /etc/ssh/ -name "ssh_host_*key*" -delete

  # slows down boot
  systemctl disable apt-daily.timer apt-daily.service apt-daily-upgrade.timer apt-daily-upgrade.service

  # unecessary services
  systemctl disable triggerhappy bluetooth wpa_supplicant

EOF
  sed -i'' 's/^#//g' etc/ld.so.preload
  cd "${REPO_DIR}"
  umount -R "${MNT_DIR}"
  losetup -D "$(losetup -l | awk '/raspbian\.img/{print $1}')"
  mv "${TMP_DIR}/raspbian.img" "${OUTPUT_NAME}"
}

check_dependencies
get_raspbian "latest"
setup_raspbian
provision_raspbian

echo -e "[+] Done."
