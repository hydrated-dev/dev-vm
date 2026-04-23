{
  description = "Direct-boot NixOS guest bundle for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };

      vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./configuration.nix ];
      };

      rootfsImage = pkgs.callPackage "${nixpkgs}/nixos/lib/make-ext4-fs.nix" {
        storePaths = [ ];
        compressImage = false;
        volumeLabel = "vzm-root";
        populateImageCommands = ''
          mkdir -p ./files
          tarball=$(find ${vm.config.system.build.rootfsTarball} -type f -name '*.tar' | head -n 1)
          test -n "$tarball"
          tar -C ./files -xf "$tarball"
        '';
      };

      kernelCommandLine = nixpkgs.lib.concatStringsSep " " (
        [
          "console=hvc0"
          "root=LABEL=vzm-root"
          "rootfstype=ext4"
          "init=/bin/init"
        ]
        ++ vm.config.boot.kernelParams
      );

      guestManifest = pkgs.writeText "manifest.json" (builtins.toJSON {
        schemaVersion = 1;
        architecture = "aarch64";
        kernel = "kernel";
        initrd = "initrd";
        rootfs = "rootfs.ext4";
        rootMode = "persistent";
        commandLine = kernelCommandLine;
        requiredDisks = [ "data" ];
      });

      guestBundle = pkgs.runCommand "guest-bundle" { } ''
        mkdir -p "$out"

        cp ${vm.config.system.build.kernel}/${vm.config.system.boot.loader.kernelFile} "$out/kernel"

        initrd_source=${vm.config.system.build.initialRamdisk}
        if [ -d "$initrd_source" ]; then
          cp "$initrd_source"/initrd "$out/initrd"
        else
          cp "$initrd_source" "$out/initrd"
        fi

        cp ${rootfsImage} "$out/rootfs.ext4"
        cp ${guestManifest} "$out/manifest.json"
      '';
    in
    {
      nixosConfigurations = {
        vm = vm;
      };

      packages.${system} = {
        guest-bundle = guestBundle;
      };
    };
}
