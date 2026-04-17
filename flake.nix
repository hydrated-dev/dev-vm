{
  description = "NixOS guest image for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      system = "aarch64-linux";

      vm = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit self; };
        modules = [ ./configuration.nix ];
      };
    in
    {
      nixosConfigurations = {
        vm = vm;
      };

      packages.${system} = {
        raw-efi = vm.config.system.build.images.raw-efi;
      };
    };
}
