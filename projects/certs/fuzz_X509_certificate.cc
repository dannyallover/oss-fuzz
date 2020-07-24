#include "X509_certificate.pb.h"
#include "X509_certificate_to_der.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const X509_certificate::X509Certificate& cert) {
  X509_certificate::CertToDER converter;
  std::vector<uint8_t> der = converter.X509CertificateToDER(cert);
  // The pointer to the vector and size will used in future fuzz targets.
  const uint8_t* buf = der.data();
  size_t len = der.size();
}