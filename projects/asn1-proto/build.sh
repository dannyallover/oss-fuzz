#!/bin/bash -eu
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Compile asn1 proto.
rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc asn1.proto --cpp_out=genfiles --proto_path=$SRC

# Compile LPM fuzzer.
$CXX $CXXFLAGS -I genfiles -I . -I libprotobuf-mutator/ -I LPM/external.protobuf/include -I include $LIB_FUZZING_ENGINE \
    $SRC/asn1_proto_main.cc genfiles/asn1.pb.cc $SRC/asn1_proto_converter.cc \
    LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    LPM/src/libprotobuf-mutator.a \
    LPM/external.protobuf/lib/libprotobuf.a \
    -o  $OUT/asn1_proto_generate \
