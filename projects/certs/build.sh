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

# Move asn1-pdu & asn1-unvirsal-types proto and converter to SRC
cp -R $SRC/fuzzing/proto/asn1/asn1-pdu/* $SRC
cp -R $SRC/fuzzing/proto/asn1/asn1-universal-types/* $SRC
# Move common file to SRC which the converters depend on
cp -R $SRC/fuzzing/proto/asn1/common/* $SRC

# Compile cert proto.
rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc asn1_pdu.proto asn1_universal_types.proto X509_certificate.proto --cpp_out=genfiles --proto_path=$SRC/

# Compile LPM fuzzer.
$CXX $CXXFLAGS -I genfiles -I . -I libprotobuf-mutator/ -I LPM/external.protobuf/include -I include $LIB_FUZZING_ENGINE \
    $SRC/fuzz.cc genfiles/X509_certificate.pb.cc genfiles/asn1_pdu.pb.cc genfiles/asn1_universal_types.pb.cc \
    $SRC/X509_certificate_to_der.cc $SRC/asn1_pdu_to_der.cc $SRC/asn1_universal_types_to_der.cc $SRC/common.cc \
    LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    LPM/src/libprotobuf-mutator.a \
    LPM/external.protobuf/lib/libprotobuf.a \
    -o  $OUT/x509_certificate_lpm \