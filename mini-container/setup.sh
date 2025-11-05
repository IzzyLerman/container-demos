#!/bin/bash


# 1. Compile the runtime
gcc -o mini-container mini-container.c -Wall
echo "Compiled successfully"

# 2. Create rootfs with overlayfs
mkdir -p rootfs/{lower,upper,work,merged}

# Extract Alpine
docker export $(docker create alpine:3.18) | tar -xC rootfs/lower/
echo "Rootfs ready"

# 3. Mount overlayfs
sudo mount -t overlay overlay \
  -o lowerdir=rootfs/lower,upperdir=rootfs/upper,workdir=rootfs/work \
  rootfs/merged
echo "Overlayfs mounted at rootfs/merged"

echo 'Ready to use. Usage examples:

sudo ./mini-container run rootfs/merged /bin/sh -c "echo 'Hello from container!'; hostname; ps aux"

MEMORY_LIMIT=104857600 PIDS_MAX=10 \
  sudo ./mini-container run rootfs/merged /demo.sh

sudo ./mini-container run rootfs/merged /bin/sh

Cleanup:
sudo umount rootfs/merged
'

