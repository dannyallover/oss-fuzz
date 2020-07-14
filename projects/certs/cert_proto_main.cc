#include "cert.pb.h"
#include "cert_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const cert_proto::X509Certificate &cert) {
  cert_proto::CertProtoConverter converter = cert_proto::CertProtoConverter();
  std::string s = converter.EncodeCert(cert);
  std::cout << s << "\n" << std::endl;
}