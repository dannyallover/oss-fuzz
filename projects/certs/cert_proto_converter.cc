#include "cert_proto_converter.h"

namespace cert_proto {

void CertProtoConverter::ParseToBits() {
  for (const uint8_t byte : encoder_) {
    for (int i = 7; i >= 0; i--) {
      if (((byte >> i) & 0x01)) {
        std::cout << "1";
      } else {
        std::cout << "0";
      }
    }
    std::cout << " ";
  }
}

std::vector<uint8_t> CertProtoConverter::EncodeCertificate(const X509Certificate& cert) {
  pdu2der = asn1_pdu::ASN1PDUProtoToDER();
  auto pdu = cert.signature_value();
  auto pdu_encoded = pdu2der.ProtoToDER(pdu);

  // ParseToBits(res);
  return pdu_encoded;
}

}  // namespace cert_proto