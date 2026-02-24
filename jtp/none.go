package jtp

// None is a tag struct meaning that no value is expected to be sent or received,
// depending on where it's used.
type None struct{}

// Nil is a nil value with the empty type
var Nil *None = nil
