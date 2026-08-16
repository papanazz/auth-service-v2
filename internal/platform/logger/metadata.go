package logger

// Metadata is a type alias, not a distinct named type: this lets
// domain/logging.Logger (and any other narrow interface elsewhere in
// this codebase) declare its methods using plain map[string]any and
// still be satisfied transparently by *Logger — no adapter needed,
// since an alias means the two spellings are the exact same type for
// interface-matching purposes.
type Metadata = map[string]any
