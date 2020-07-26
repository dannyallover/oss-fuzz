#include "X509_certificate_to_der.h"

namespace X509_certificate {

template <typename T>
void CertToDER::EncodeBitString(const T obj_with_bit_string) {
  std::vector<uint8_t> der;
  if (obj_with_bit_string.has_pdu()) {
    der = pdu_to_der.PDUToDER(obj_with_bit_string.pdu());
  } else {
    der = primitive_types_to_der.EncodeBitString(
        obj_with_bit_string.bit_string());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

template <typename T>
void CertToDER::EncodeInteger(T obj_with_int) {
  std::vector<uint8_t> der;
  if (obj_with_int.has_pdu()) {
    der = pdu_to_der.PDUToDER(obj_with_int.pdu());
  } else {
    der = primitive_types_to_der.EncodeInteger(obj_with_int.integer());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

// this will change later
void CertToDER::EncodeAlgorithmIdentifier(const AlgorithmIdentifier& alg_id) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(alg_id.pdu());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeExtensions(const Extensions& extensions) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(extensions.pdu());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
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
  EncodeSubjectPublicKey(subject_public_key_info.subject_public_key());
}

void CertToDER::EncodeSubject(const Subject& subject) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(subject.name().pdu());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTime(const Time& time) {
  std::vector<uint8_t> der;
  if (time.has_pdu()) {
    der = pdu_to_der.PDUToDER(time.pdu());
  } else if (time.has_utc_time()) {
    der = primitive_types_to_der.EncodeUTCTime(time.utc_time());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeValidity(const Validity& validity) {
  EncodeTime(validity.not_before().time());
  EncodeTime(validity.not_after().time());
}

void CertToDER::EncodeIssuer(const Issuer& issuer) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(issuer.name().pdu());
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeSignature(const Signature& signature) {
  EncodeAlgorithmIdentifier(signature.algorithm_identifier());
}

void CertToDER::EncodeCertificateSerialNumber(
    const CertificateSerialNumber& cert_serial_num) {
  EncodeInteger(cert_serial_num);
}

void CertToDER::EncodeVersion(const Version& version) {
  std::vector<uint8_t> der;
  if (version.has_pdu()) {
    der = pdu_to_der.PDUToDER(version.pdu());
  } else {
    der = {0x02, 0x01, static_cast<uint8_t>(version.version_number())};
  }
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
  EncodeAlgorithmIdentifier(signature_algorithm.algorithm_identifier());
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