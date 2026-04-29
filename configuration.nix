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

  programs.ssh.extraConfig = ''
    Host github.com
      HostName github.com
      Port 22
      ProxyCommand ${pkgs.socat}/bin/socat - VSOCK-CONNECT:2:2223
  '';

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
    socat
    vim
  ];

  nixpkgs.config.allowUnfree = true;

  environment.variables = {
    EDITOR = "vim";
    VZM_ROOT_MODE = "persistent";
    VZM_DATA_MOUNT = "/data";
    HTTP_PROXY = "http://127.0.0.1:3128";
    HTTPS_PROXY = "http://127.0.0.1:3128";
    http_proxy = "http://127.0.0.1:3128";
    https_proxy = "http://127.0.0.1:3128";
    NO_PROXY = "localhost,127.0.0.1,::1";
    no_proxy = "localhost,127.0.0.1,::1";
    SSL_CERT_FILE = "/run/vzm/ca-bundle.crt";
    NIX_SSL_CERT_FILE = "/run/vzm/ca-bundle.crt";
  };

  # The interactive `nix` client may see the proxy environment above, but
  # actual downloads are often performed by the system nix-daemon. Propagate
  # the same proxy/CA settings there so substituter fetches also traverse the
  # host HTTPS proxy and trigger approvals instead of attempting direct DNS.
  systemd.services.nix-daemon.environment = {
    HTTP_PROXY = "http://127.0.0.1:3128";
    HTTPS_PROXY = "http://127.0.0.1:3128";
    http_proxy = "http://127.0.0.1:3128";
    https_proxy = "http://127.0.0.1:3128";
    NO_PROXY = "localhost,127.0.0.1,::1";
    no_proxy = "localhost,127.0.0.1,::1";
    SSL_CERT_FILE = "/run/vzm/ca-bundle.crt";
    NIX_SSL_CERT_FILE = "/run/vzm/ca-bundle.crt";
  };

  systemd.services.vzm-proxy-ca = {
    description = "Fetch the vzm HTTPS proxy CA from the host";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-modules-load.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      mkdir -p /run/vzm
      ${pkgs.socat}/bin/socat -u VSOCK-CONNECT:2:3129 - > /run/vzm/proxy-ca.pem
      cat /etc/ssl/certs/ca-certificates.crt /run/vzm/proxy-ca.pem > /run/vzm/ca-bundle.crt
      chmod 0644 /run/vzm/proxy-ca.pem /run/vzm/ca-bundle.crt
    '';
  };

  systemd.services.vzm-https-proxy = {
    description = "Expose the host vzm HTTPS proxy on localhost";
    wantedBy = [ "multi-user.target" ];
    after = [ "vzm-proxy-ca.service" ];
    requires = [ "vzm-proxy-ca.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:3128,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:3128";
      Restart = "always";
      RestartSec = "1s";
    };
  };

  systemd.services.vzm-port-forward-3000 = {
    description = "Expose guest localhost:3000 over vsock";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-modules-load.service" "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:3000,fork,reuseaddr TCP:127.0.0.1:3000";
      Restart = "always";
      RestartSec = "1s";
    };
  };

  systemd.services.vzm-port-forward-5173 = {
    description = "Expose guest localhost:5173 over vsock";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-modules-load.service" "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat VSOCK-LISTEN:5173,fork,reuseaddr TCP:127.0.0.1:5173";
      Restart = "always";
      RestartSec = "1s";
    };
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
