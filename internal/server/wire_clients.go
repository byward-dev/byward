package server

import "github.com/byward-dev/byward/internal/registration"

// newCIMDRegistry is registration.NewCIMDRegistry; tests replace it to see the wired host lists.
var newCIMDRegistry = registration.NewCIMDRegistry
