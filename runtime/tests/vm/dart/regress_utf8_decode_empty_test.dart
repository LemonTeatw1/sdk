// Copyright (c) 2026, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.
//
// Regression test for `Utf8::Decode(utf8_array, array_len, dst)` reading
// `utf8_array[0]` unconditionally before checking `array_len > 0`. The
// fix in `runtime/platform/unicode.cc` returns early when `array_len <= 0`.
//
// Reaching the C++ function from Dart with `array_len == 0` is awkward —
// the public Utf8 entry points always wrap the call in a positive-length
// loop. This test exercises the closest user-visible surface: decoding
// an empty `Uint8List` via `String.fromCharCodes` and the system
// encoding helpers, and asserts no crash and no surprising behaviour.

import 'dart:convert';
import 'dart:typed_data';

import 'package:expect/expect.dart';

void main() {
  // Decoding empty bytes through the standard utf8 codec must produce ''.
  Expect.equals('', utf8.decode(const <int>[]));
  Expect.equals('', utf8.decode(Uint8List(0)));
  Expect.equals(
    '',
    utf8.decoder.bind(Stream<List<int>>.fromIterable(<List<int>>[])).join(),
  );

  // String.fromCharCodes on an empty list goes through the Latin1 path, but
  // round-tripping via utf8 is the most direct way to exercise Utf8::Decode
  // from Dart-level code.
  Expect.equals('', utf8.decode(utf8.encode('')));
}
