{
  modulesPath,
  pkgs,
  lib,
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

  # A raw EFI disk image should boot as removable media without relying on
  # firmware NVRAM variables.
  boot.loader.systemd-boot.enable = false;
  boot.loader.grub = {
    enable = true;
    device = "nodev";
    efiSupport = true;
    efiInstallAsRemovable = true;
  };
  boot.loader.efi.canTouchEfiVariables = false;

  image.baseName = "nixos-vzm";
  image.extension = "raw";
  image.modules = [ ];

  virtualisation.diskSize = 12 * 1024;

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

  environment.systemPackages = with pkgs; [
    vim
  ];

  nixpkgs.config.allowUnfree = true;

  environment.variables.EDITOR = "vim";
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
