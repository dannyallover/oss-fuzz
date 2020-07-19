#include "cert.pb.h"
#include "cert_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const asn1_proto::PDU& asn1) {
  asn1_proto::ASN1ProtoConverter converter = asn1_proto::ASN1ProtoConverter();
  std::vector<uint8_t> der = converter.ProtoToDER(asn1);
  // The pointer to the array and size will used in future fuzz targets.
  uint8_t* ptr = &der[0];
  size_t size = der.size();
}