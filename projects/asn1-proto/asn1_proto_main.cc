#include "asn1.pb.h"
#include "asn1_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const asn1_proto::PDU &asn1) {
  asn1_proto::ASN1ProtoConverter converter = asn1_proto::ASN1ProtoConverter();
  std::string s = converter.ProtoToDER(asn1);
  std::cout << s << "\n" << std::endl;
}
