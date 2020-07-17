#!/bin/bash -eux
#
# Copyright 2016 Google Inc.
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
CFLAGS="$CFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"
CXXFLAGS="$CXXFLAGS -DBORINGSSL_UNSAFE_FUZZER_MODE"

CMAKE_DEFINES="-DBORINGSSL_ALLOW_CXX_RUNTIME=1"
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CMAKE_DEFINES+=" -DOPENSSL_NO_ASM=1"
fi

cmake -GNinja -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      $CMAKE_DEFINES $SRC/boringssl/
ninja


fuzzerFiles=$(find $SRC/boringssl/fuzz/ -name "*.cc")

find . -name "*.a"

rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc asn1.proto --cpp_out=genfiles --proto_path=$SRC

$CXX $CXXFLAGS -I genfiles -I . -I libprotobuf-mutator/ -I LPM/external.protobuf/include -I include $LIB_FUZZING_ENGINE \
    $SRC/asn1_proto_main.cc genfiles/asn1.pb.cc $SRC/asn1_proto_converter.cc \
    -I $SRC/boringssl/include ./ssl/libssl.a  ./crypto/libcrypto.a \
    LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    LPM/src/libprotobuf-mutator.a \
    LPM/external.protobuf/lib/libprotobuf.a \
    -o  $OUT/asn1_proto_generate_1 \

$CXX $CXXFLAGS -std=c++11 \
  -o $OUT/asn1_proto_generate_2 $LIB_FUZZING_ENGINE $SRC/fuzz.cc \
  -I $SRC/boringssl/include ./ssl/libssl.a  ./crypto/libcrypto.a