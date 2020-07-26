#include "X509_certificate_to_der.h"

namespace X509_certificate {

template <typename T>
void CertToDER::EncodeBitString(const T& obj_with_bit_string) {
  if (obj_with_bit_string.has_pdu()) {
    return EncodePDU(obj_with_bit_string.pdu());
  }
  std::vector<uint8_t> der =
      types_to_der.EncodeBitString(obj_with_bit_string.bit_string());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

template <typename T>
void CertToDER::EncodeInteger(const T& obj_with_int) {
  if (obj_with_int.has_pdu()) {
    return EncodePDU(obj_with_int.pdu());
  }
  std::vector<uint8_t> der = types_to_der.EncodeInteger(obj_with_int.integer());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

template <typename T>
void CertToDER::EncodeAlgorithmIdentifier(const T& obj_with_alg_id) {
  if (obj_with_alg_id.has_pdu()) {
    return EncodePDU(obj_with_alg_id.pdu());
  }
  std::vector<uint8_t> der = types_to_der.EncodeAlgorithmIdentifier(
      obj_with_alg_id.algorithm_identifier());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodePDU(const asn1_pdu::PDU& pdu) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(pdu);
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeExtensions(const Extensions& extensions) {
  EncodePDU(extensions.pdu());
}

void CertToDER::EncodeIssuerUniqueId(const IssuerUniqueId& issuer_unique_id) {
  EncodeBitString(issuer_unique_id.unique_identifier());
}

void CertToDER::EncodeSubjectPublicKey(
    const SubjectPublicKey& subject_public_key) {
  EncodeBitString(subject_public_key);
}

void CertToDER::EncodeSubjectPublicKeyInfo(
    const SubjectPublicKeyInfo& subject_public_key_info) {
  encoder_.push_back(0x30);
  size_t len_pos = encoder_.size();
  EncodeAlgorithmIdentifier(subject_public_key_info);
  EncodeSubjectPublicKey(subject_public_key_info.subject_public_key());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeSubject(const Subject& subject) {
  EncodePDU(subject.name().pdu());
}

void CertToDER::EncodeTime(const Time& time) {
  if (time.has_pdu()) {
    return EncodePDU(time.pdu());
  }

  std::vector<uint8_t> der;
  if (time.has_utc_time()) {
    der = types_to_der.EncodeUTCTime(time.utc_time());
  } else {
    der = types_to_der.EncodeGeneralizedTime(time.generalized_time());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeValidity(const Validity& validity) {
  encoder_.push_back(0x30);
  size_t len_pos = encoder_.size();
  EncodeTime(validity.not_before().time());
  EncodeTime(validity.not_after().time());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeIssuer(const Issuer& issuer) {
  EncodePDU(issuer.name().pdu());
}

void CertToDER::EncodeSignature(const Signature& signature) {
  EncodeAlgorithmIdentifier(signature);
}

void CertToDER::EncodeCertificateSerialNumber(
    const CertificateSerialNumber& cert_serial_num) {
  EncodeInteger(cert_serial_num);
}

void CertToDER::EncodeVersion(const Version& version) {
  if (version.has_pdu()) {
    return EncodePDU(version.pdu());
  }
  std::vector<uint8_t> der = {0x02, 0x01,
                              static_cast<uint8_t>(version.version_number())};
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTBSCertificate(const TBSCertificate& tbs_certificate) {
  encoder_.push_back(0x30);
  size_t len_pos = encoder_.size();
  EncodeVersion(tbs_certificate.version());
  EncodeCertificateSerialNumber(tbs_certificate.serial_number());
  EncodeSignature(tbs_certificate.signature());
  EncodeIssuer(tbs_certificate.issuer());
  EncodeValidity(tbs_certificate.validity());
  EncodeSubject(tbs_certificate.subject());
  EncodeSubjectPublicKeyInfo(tbs_certificate.subject_public_key_info());
  if (tbs_certificate.has_issuer_unique_id()) {
    EncodeIssuerUniqueId(tbs_certificate.issuer_unique_id());
  }
  EncodeExtensions(tbs_certificate.extensions());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeSignatureAlgorithm(
    const SignatureAlgorithm& signature_algorithm) {
  EncodeAlgorithmIdentifier(signature_algorithm);
}

void CertToDER::EncodeSignatureValue(const SignatureValue& signature_value) {
  EncodeBitString(signature_value);
}

void CertToDER::EncodeX509Certificate(const X509Certificate& X509_certificate) {
  encoder_.push_back(0x30);
  size_t len_pos = encoder_.size();
  EncodeTBSCertificate(X509_certificate.tbs_certificate());
  EncodeSignatureValue(X509_certificate.signature_value());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

std::vector<uint8_t> CertToDER::X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  encoder_.clear();
  EncodeX509Certificate(X509_certificate);
  return encoder_;
}

}  // namespace X509_certificate