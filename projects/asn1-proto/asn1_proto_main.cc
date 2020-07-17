#include "asn1.pb.h"
#include "asn1_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const asn1_proto::PDU &asn1) {
  asn1_proto::ASN1ProtoConverter converter = asn1_proto::ASN1ProtoConverter();
  std::vector<uint8_t> encoded = converter.ProtoToDER(asn1);
}
