// Package zlog is a stdlib-only async structured logger for Go.
//
// Fast path design notes:
//   - disabled log calls perform only an atomic level check;
//   - typed Attr constructors avoid maps and reflection;
//   - encoders use append-style strconv operations;
//   - async mode decouples producers from slow writers;
//   - slow features such as Any, caller, stack, redaction copies, slog bridging and JSON marshaling are opt-in or documented slow paths.
package zlog
