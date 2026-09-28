# Go module publication / pkg.go.dev discovery

This repository now uses the canonical module path:

`github.com/blackmore-technology-group/ENTITY-GO-CLEANROOM`

The registry package smoke workflow verifies that exact module identity, runs `go test ./...`, and confirms all packages are listable.

## Remaining external release step

The repository currently needs an intentional semantic-version release tag before it should be treated as a normal versioned Go module distribution surface.

Before creating a release tag:

1. confirm the intended module version corresponds to the exact source/campaign being distributed;
2. run the existing clean-room verification and registry package smoke checks;
3. do not move or rewrite an existing historical tag;
4. create a new semantic-version tag only after the source/version boundary is reviewed;
5. request/trigger normal Go module proxy/pkg.go.dev discovery for that tagged version.

pkg.go.dev discovery does not require embedding registry credentials in this repository.

## Evidence boundary

A pkg.go.dev listing makes this BTG-controlled Go baseline easier to find and import. It does not constitute unrelated third-party validation or an independently authored ENTITY implementation.
