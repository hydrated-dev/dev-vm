{
  modulesPath,
  pkgs,
  lib,
  ...
}:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    (modulesPath + "/installer/netboot/netboot-minimal.nix")
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  programs.nix-ld.enable = true;

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      AllowUsers = [ "braden" ];
      AllowAgentForwarding = true;
    };
  };

  security = {
    sudo.wheelNeedsPassword = false;
    pam.enableUMask = true;
    loginDefs.settings.UMASK = "007";
  };

  systemd.user.extraConfig = ''
    DefaultUMask=0007
  '';

  boot.initrd.availableKernelModules = [
    "virtio_blk"
    "virtio_pci"
    "virtio_scsi"
    "xhci_pci"
    "usbhid"
    "usb_storage"
    "sr_mod"
  ];
  boot.initrd.kernelModules = [
    "virtiofs"
    "vsock"
    "vmw_vsock_virtio_transport"
  ];
  boot.kernelModules = [
    "vsock"
    "vmw_vsock_virtio_transport"
  ];
  boot.extraModulePackages = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.supportedFilesystems.zfs = lib.mkForce false;

  networking.useDHCP = false;
  networking.interfaces = { };
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 22 ];

  systemd.sockets.vsock-ssh = {
    description = "Expose guest SSH over vsock port 2222";
    wantedBy = [ "sockets.target" ];
    listenStreams = [ "vsock::2222" ];
    socketConfig = {
      Accept = true;
      NoDelay = true;
    };
  };

  systemd.services."vsock-ssh@" = {
    description = "Proxy vsock SSH connections to localhost:22";
    requires = [ "sshd.service" ];
    after = [ "sshd.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd 127.0.0.1:22";
      StandardInput = "socket";
      StandardOutput = "socket";
      StandardError = "journal";
      PrivateNetwork = false;
    };
  };

  systemd.services.vzm-data-disk = {
    description = "Prepare and mount the persistent vzm data disk";
    wantedBy = [ "multi-user.target" ];
    wants = [ "systemd-udev-settle.service" ];
    after = [
      "systemd-udev-settle.service"
      "local-fs.target"
    ];
    unitConfig.ConditionPathExists = "/dev/vda";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      mkdir -p /data
      if ! ${pkgs.util-linux}/bin/blkid /dev/vda >/dev/null 2>&1; then
        ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -L vzm-data /dev/vda
      fi
      if ! ${pkgs.util-linux}/bin/mountpoint -q /data; then
        ${pkgs.util-linux}/bin/mount -t ext4 /dev/vda /data
      fi
      chown braden:braden /data
      chmod 700 /data
    '';
  };

  environment.systemPackages = with pkgs; [
    vim
  ];

  nixpkgs.config.allowUnfree = true;

  environment.variables = {
    EDITOR = "vim";
    VZM_ROOT_MODE = "ephemeral";
    VZM_DATA_MOUNT = "/data";
  };

  programs.zsh.enable = true;
  users.defaultUserShell = pkgs.zsh;

  time.timeZone = "America/Chicago";

  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 7d";
  };

  users.groups.braden = { };

  users.users.braden = {
    isNormalUser = true;
    home = "/home/braden";
    homeMode = "700";
    createHome = true;
    group = "braden";
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxUPJoiKdlvEq4+i4ZCl7lj1NOSgT7BsspqfgncdJKQVV5CKVZ1hnn/MNO4cAXRFOWjXkzowN+7mJZm8cVhP18="
    ];
  };

  system.stateVersion = "25.11";
}
