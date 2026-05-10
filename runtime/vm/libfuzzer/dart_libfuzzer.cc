// Copyright (c) 2019, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "bin/dartutils.h"
#include "platform/text_buffer.h"
#include "platform/unicode.h"
#include "platform/utils.h"
#include "vm/json_writer.h"

// Defines target function.
static int target = 0;

// Make any read past `size` detectable by ASan/MSan/HWASan: copy `Data`
// into a heap allocation of *exactly* `size` bytes so the byte
// immediately after the input is in a poisoned redzone. libFuzzer's
// own input buffer is over-allocated and would mask out-of-bounds
// reads of a few bytes past `size`, including the common
// `array_len == 0` contract violation in Utf8::Decode.
//
// The caller owns the returned pointer and must `free` it.
static uint8_t* CopyToExactBuffer(const uint8_t* Data, size_t size) {
  uint8_t* p = static_cast<uint8_t*>(malloc(size));
  if (size > 0 && p != nullptr) {
    memcpy(p, Data, size);
  }
  return p;
}

// Target function that stresses some unicode methods.
// Found: http://dartbug.com/36235
static int TestUnicode(const uint8_t* Data, size_t Size) {
  // Use an exact-sized copy so a read past `Size` (e.g. an unconditional
  // `utf8_array[0]` when `Size == 0`) is flagged by the sanitizer rather
  // than absorbed by libFuzzer's input padding.
  uint8_t* exact = CopyToExactBuffer(Data, Size);
  dart::Utf8::Type type = dart::Utf8::kLatin1;
  dart::Utf8::CodeUnitCount(exact, Size, &type);
  dart::Utf8::IsValid(exact, Size);
  int32_t dst = 0;
  dart::Utf8::Decode(exact, Size, &dst);
  uint16_t dst16[1024];
  dart::Utf8::DecodeToUTF16(exact, Size, dst16, 1024);
  int32_t dst32[1024];
  dart::Utf8::DecodeToUTF32(exact, Size, dst32, 1024);
  dart::Utf8::ReportInvalidByte(exact, Size, 1024);
  free(exact);
  return 0;
}

// Target function that stresses various utilities.
// Found: http://dartbug.com/36818
static int TestUtilities(const uint8_t* Data, size_t Size) {
  dart::Utils::StringHash(reinterpret_cast<const char*>(Data), Size);
  dart::bin::DartUtils::SniffForMagicNumber(Data, Size);
  // Text buffer.
  dart::TextBuffer buffer(1);
  for (size_t i = 0; i < Size; i++) {
    buffer.AddChar(Data[i]);
  }
  if (static_cast<size_t>(buffer.length()) != Size) return 1;
  buffer.AddRaw(Data, Size);
  if (static_cast<size_t>(buffer.length()) != 2 * Size) return 1;
  free(buffer.Steal());
  buffer.AddRaw(Data, Size);
  if (static_cast<size_t>(buffer.length()) != Size) return 1;
  // Json writer.
  dart::JSONWriter writer(1);
  writer.OpenObject("object");
  writer.AppendBytes(Data, Size);
  writer.CloseObject();
  for (size_t i = 0; i < Size; i++) {
    writer.PrintValue(static_cast<intptr_t>(Data[i]));
  }
  writer.PrintValueBase64(Data, Size);
  return 0;
}

// Dart VM specific initialization.
static int InitDartVM() {
  // TODO(ajcbik): one-time setup of Dart VM.
  return 0;
}

// Libfuzzer one time initialization.
extern "C" int LLVMFuzzerInitialize(int* argc_in, char*** argv_in) {
  // Parse --t=<target> from command line.
  int argc = *argc_in;
  char** argv = *argv_in;
  while (--argc > 0) {
    char* ptr = *++argv;
    if (*ptr++ == '-' && *ptr++ == '-' && *ptr++ == 't' && *ptr++ == '=') {
      target = atoi(ptr);
    }
  }
  // Initialize Dart VM.
  return InitDartVM();
}

// Libfuzzer target functions:
//  0 : unicode
//  1 : utilities
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  switch (target) {
    case 0:
      return TestUnicode(Data, Size);
    case 1:
      return TestUtilities(Data, Size);
    default:
      fprintf(stderr, "dart_libfuzzer: invalid target --t=%d\n", target);
      return 1;
  }
}
