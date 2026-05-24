# nix/packages.nix — FETIH Agent package built with uv2nix
{ inputs, ... }:
{
  perSystem =
    { pkgs, inputs', ... }:
    let
      fetihAgent = pkgs.callPackage ./fetih.nix {
        inherit (inputs) uv2nix pyproject-nix pyproject-build-systems;
        npm-lockfile-fix = inputs'.npm-lockfile-fix.packages.default;
        # Only embed clean revs — dirtyRev doesn't represent any upstream
        # commit, so comparing it would always claim "update available".
        rev = inputs.self.rev or null;
      };
    in
    {
      packages = {
        default = fetihAgent;
        tui = fetihAgent.fetihTui;
        web = fetihAgent.fetihWeb;

        fix-lockfiles = fetihAgent.fetihNpmLib.mkFixLockfiles {
          packages = [ fetihAgent.fetihTui fetihAgent.fetihWeb ];
        };
      };
    };
}
