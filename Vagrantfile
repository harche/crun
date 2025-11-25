# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "perk/ubuntu-2204-arm64"

  config.vm.provider "qemu" do |qe|
    qe.memory = "2048"
    qe.smp = 2
    qe.arch = "aarch64"
    qe.machine = "virt,accel=hvf,highmem=on"
    qe.cpu = "host"
    qe.net_device = "virtio-net-pci"
  end

  # Sync the crun source directory
  config.vm.synced_folder ".", "/home/vagrant/crun", type: "rsync",
    rsync__exclude: [".git/", "*.o", "*.lo", "*.la", ".libs/", "autom4te.cache/"]

  # Install build dependencies
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y \
      autoconf automake libtool \
      gcc make pkg-config \
      libcap-dev \
      libseccomp-dev \
      libsystemd-dev \
      python3 \
      git \
      go-md2man
  SHELL
end
