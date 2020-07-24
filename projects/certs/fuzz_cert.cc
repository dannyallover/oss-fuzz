#include "cert.pb.h"
#include "cert_to_der.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const cert_proto::X509Certificate& cert) {
  cert_proto::CertProtoConverter converter = cert_proto::CertProtoConverter();
  std::vector<uint8_t> der = converter.EncodeCertificate(cert);
  // The pointer to the array and size will used in future fuzz targets.
  uint8_t* ptr = &der[0];
  size_t size = der.size();
}