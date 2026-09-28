# Go module publication / pkg.go.dev discovery

This repository now uses the canonical module path:

`github.com/blackmore-technology-group/ENTITY-GO-CLEANROOM`

The registry package smoke workflow verifies that exact module identity, runs `go test ./...`, and confirms all packages are listable.

## Distribution version boundary

The intended first normal versioned distribution tag for the current qualified campaign is:

`v3.4.2`

That tag identifies the BTG-controlled v3.4.2 Global Passport campaign. It does not rename ENTITY Protocol 1.0 and it does not convert BTG-controlled evidence into independent validation.

## Remaining external release step

Before creating `v3.4.2`:

1. confirm `main` is the exact source/campaign already qualified by dependency review, clean-room verification and registry package smoke;
2. confirm no existing `v3.4.2` tag exists and never move or rewrite a historical tag;
3. create `v3.4.2` at that reviewed commit;
4. verify the tagged module still passes `go test ./...` and resolves as `github.com/blackmore-technology-group/ENTITY-GO-CLEANROOM@v3.4.2`;
5. request/trigger normal Go module proxy/pkg.go.dev discovery for that tagged version.

pkg.go.dev discovery does not require embedding registry credentials in this repository.

## Evidence boundary

A pkg.go.dev listing makes this BTG-controlled Go baseline easier to find and import. It does not constitute unrelated third-party validation or an independently authored ENTITY implementation.
