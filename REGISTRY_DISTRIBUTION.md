# Go module distribution boundary

This repository is a BTG-controlled ENTITY clean-room/conformance baseline. The canonical module path exists so Go developers and pkg.go.dev can resolve the source correctly; it does not turn BTG-controlled conformance evidence into independent validation.

Future semantic-version tags intended for Go discovery must identify the exact source and campaign they package. Existing sealed inputs, expected classifications, hashes, and fail-closed behavior must not be altered to satisfy registry packaging.
