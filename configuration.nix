{
  modulesPath,
  pkgs,
  lib,
  config,
  ...
}:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  programs.nix-ld.enable = true;

  services.openssh = {
    enable = true;
    startWhenNeeded = lib.mkForce false;
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

  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;

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
  boot.kernelParams = [ "console=hvc0" ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/vzm-root";
    fsType = "ext4";
  };

  networking.useDHCP = false;
  networking.hostName = "vzm-guest";
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
    unitConfig.ConditionPathExists = "/dev/vdb";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      mkdir -p /data
      if ! ${pkgs.util-linux}/bin/blkid /dev/vdb >/dev/null 2>&1; then
        ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -L vzm-data /dev/vdb
      fi
      if ! ${pkgs.util-linux}/bin/mountpoint -q /data; then
        ${pkgs.util-linux}/bin/mount -t ext4 /dev/vdb /data
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
    VZM_ROOT_MODE = "persistent";
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

  environment.etc."skel/.zshrc".text = ''
    # Prevent zsh-newuser-install from hijacking the console on first login.
  '';

  boot.postBootCommands =
    ''
      if [ -f /nix-path-registration ]; then
        ${config.nix.package.out}/bin/nix-store --load-db < /nix-path-registration
        rm /nix-path-registration
      fi
    ''
    + ''
      ${config.nix.package.out}/bin/nix-env -p /nix/var/nix/profiles/system --set /run/current-system
    '';

  system.stateVersion = "25.11";
}
