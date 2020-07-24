#include "X509_certificate_to_der.h"

namespace X509_certificate {

void CertToDER::EncodeExtensions(const Extensions& extensions) {
  std::vector<uint8_t> der =
      pdu_to_der.PDUToDER(extensions.invalid_extensions());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeValidity(const Validity& validity) {
  std::vector<uint8_t> der;
  if (validity.not_before().has_invalid_not_before()) {
    der = pdu_to_der.PDUToDER(validity.not_before().invalid_not_before());
  } else {
    der = primitive_types_to_der.EncodeUTCTime(
        validity.not_before().valid_not_before());
  }
  if (validity.not_after().has_invalid_not_after()) {
    der = pdu_to_der.PDUToDER(validity.not_after().invalid_not_after());
  } else {
    der = primitive_types_to_der.EncodeUTCTime(
        validity.not_after().valid_not_after());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeCertificateSerialNumber(
    const CertificateSerialNumber& cert_serial_num) {
  std::vector<uint8_t> der;
  if (cert_serial_num.has_invalid_serial_number()) {
    der = pdu_to_der.PDUToDER(cert_serial_num.invalid_serial_number());
  } else {
    der = primitive_types_to_der.EncodeInteger(cert_serial_num.valid_serial_number());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeVersion(const Version& version) {
  std::vector<uint8_t> der;
  if (version.has_invalid_version()) {
    der = pdu_to_der.PDUToDER(version.invalid_version());
  } else {
    der = {0x02, 0x01, static_cast<uint8_t>(version.valid_version())};
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTBSCertificate(const TBSCertificate& tbs_certificate) {
  encoder_.push_back(0x30);
  size_t len_helper = encoder_.size();
  EncodeVersion(tbs_certificate.version());
  EncodeCertificateSerialNumber(tbs_certificate.serial_number());
  EncodeValidity(tbs_certificate.validity());
  EncodeExtensions(tbs_certificate.extensions());
  encoder_.insert(encoder_.begin() + len_helper, encoder_.size() - len_helper);
}

void CertToDER::EncodeSignatureValue(const SignatureValue& signature_value) {
  std::vector<uint8_t> der;
  if (signature_value.has_invalid_signature_value()) {
    der = pdu_to_der.PDUToDER(signature_value.invalid_signature_value());
  } else {
    der = primitive_types_to_der.EncodeBitString(
        signature_value.valid_signature_value());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeX509Certificate(const X509Certificate& X509_certificate) {
  encoder_.push_back(0x30);
  size_t len_helper = encoder_.size();
  EncodeTBSCertificate(X509_certificate.tbs_certificate());
  EncodeSignatureValue(X509_certificate.signature_value());
  encoder_.insert(encoder_.begin() + len_helper, encoder_.size() - len_helper);
}

std::vector<uint8_t> CertToDER::X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  encoder_.clear();
  EncodeX509Certificate(X509_certificate);
  return encoder_;
}

}  // namespace X509_certificate