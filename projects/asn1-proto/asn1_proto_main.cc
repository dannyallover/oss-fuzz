#include "asn1.pb.h"
#include "asn1_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

#include <cstdint>
#include <memory>
#include <string>
#include <iostream>
#include <cstddef>
#include <stdint.h>
#include <stdlib.h>

DEFINE_PROTO_FUZZER(const asn1_proto::ASN1Object& asn1) {
  asn1_proto::ASN1ProtoConverter converter = asn1_proto::ASN1ProtoConverter();
  std::string s = converter.ProtoToDER(asn1);
  std::cout<< s << "\n" << std::endl;
}
