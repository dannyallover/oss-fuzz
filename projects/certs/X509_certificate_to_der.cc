#include "X509_certificate_to_der.h"

namespace x509_certificate {

void CertToDER::Encode(const AlgorithmIdentifier& algorithm_identifier) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der_.size();

  der_.insert(der_.end(), algorithm_identifier.object_identifier().begin(),
              algorithm_identifier.object_identifier().end());
  der_.insert(der_.end(), algorithm_identifier.parameters().begin(),
              algorithm_identifier.parameters().end());

  // The fields of |algorithm_identifier| are wrapped around a sequence (RFC
  // 5280, 4.1.1.2).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der_| subtracted by |tag_len_pos|
  // equates to the size of the value of |algorithm_identifier|.
  EncodeTagAndLength(0x30, der_.size() - tag_len_pos, tag_len_pos, der_);
}

void CertToDER::Encode(const asn1_universal_types::BitString& bit_string) {
  std::vector<uint8_t> der_bit_str = u_types_to_der.EncodeBitString(bit_string);
  der_.insert(der_.end(), der_bit_str.begin(), der_bit_str.end());
}

void CertToDER::Encode(const asn1_universal_types::Integer& integer) {
  std::vector<uint8_t> der_int = u_types_to_der.EncodeInteger(integer);
  der_.insert(der_.end(), der_int.begin(), der_int.end());
}

void CertToDER::Encode(const VersionNumber& version) {
  // |version| is Context-specific with tag_number 0 (RFC 5280, 4.1 & 4.1.2.1).
  // Takes on values 0, 1 and 2, so only require length of 1 to
  // encode it (RFC 5280, 4.1 & 4.1.2.1).
  std::vector<uint8_t> der_ver_num = {0x80, 0x01, static_cast<uint8_t>(version)};
  der_.insert(der_.end(), der_ver_num.begin(), der_ver_num.end());
}

void CertToDER::Encode(const asn1_universal_types::UTCTime& utc_time) {
  std::vector<uint8_t> der_utc_time = u_types_to_der.EncodeUTCTime(utc_time);
  der_.insert(der_.end(), der_utc_time.begin(), der_utc_time.end());
}

void CertToDER::Encode(const asn1_universal_types::GeneralizedTime& generalized_time) {
  std::vector<uint8_t> der_generalized_time =
      u_types_to_der.EncodeGeneralizedTime(generalized_time);
  der_.insert(der_.end(), der_generalized_time.begin(),
              der_generalized_time.end());
}

void CertToDER::Encode(const TimeChoice& val) {
  // The |Time| field either has an UTCTime or a GeneralizedTime (RFC 5280, 4.1
  // & 4.1.2.5).
  if (val.has_utc_time()) {
    return Encode(val.utc_time());
  }
  return Encode(val.generalized_time());
}

void CertToDER::Encode(const ValidityValue& validity) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der_.size();

  Encode(validity.not_before().time());
  Encode(validity.not_after().time());

  // The fields of |Validity| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der_| subtracted by |tag_len_pos|
  // equates to the size of the value of |validity|.
  EncodeTagAndLength(0x30, der_.size() - tag_len_pos, tag_len_pos, der_);
}

void CertToDER::Encode(
    const SubjectPublicKeyInfoValue& subject_public_key_info) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der_.size();

  Encode(subject_public_key_info.algorithm_identifier());
  Encode(subject_public_key_info.subject_public_key());

  // The fields of |subject_public_key_info| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der_| subtracted by |tag_len_pos|
  // equates to the size of the value of |subject_public_key_info|.
  EncodeTagAndLength(0x30, der_.size() - tag_len_pos, tag_len_pos, der_);
}

void CertToDER::Encode(const TBSCertificateValue& tbs_certificate) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der_.size();

  Encode(tbs_certificate.version());
  Encode(tbs_certificate.serial_number());
  Encode(tbs_certificate.signature_algorithm());
  Encode(tbs_certificate.issuer().name());
  Encode(tbs_certificate.validity());
  Encode(tbs_certificate.subject().name());
  Encode(tbs_certificate.subject_public_key_info());

  // Preserve to later backtrack and explicitly set tag.
  size_t pos_of_tag;
  // RFC 5280, 4.1: |issuer_unique_id| and |subject_unique_id|
  // are only set for v2 and v3 and |extensions| only set for v3.
  // However, set |issuer_unique_id|, |subject_unique_id|, and |extensions|
  // independently of the version number for interesting inputs.
  if (tbs_certificate.has_issuer_unique_id()) {
    pos_of_tag = der_.size();
    Encode(tbs_certificate.issuer_unique_id().unique_identifier());
    // |issuer_unqiue_id| is Context-specific with tag_number 1 (RFC 5280, 4.1
    // & 4.1.2.8).
    der_[pos_of_tag] = 0x81;
  }
  if (tbs_certificate.has_subject_unique_id()) {
    pos_of_tag = der_.size();
    Encode(tbs_certificate.subject_unique_id().unique_identifier());
    // |subject_unqiue_id| is Context-specific with tag_number 2 (RFC 5280, 4.1
    // & 4.1.2.8).
    der_[pos_of_tag] = 0x82;
  }
  if (tbs_certificate.has_extensions()) {
    pos_of_tag = der_.size();
    Encode(tbs_certificate.extensions());
    // |extensions| is Context-specific with tag_number 3 (RFC 5280, 4.1
    // & 4.1.2.8).
    der_[pos_of_tag] = 0x83;
  }

  // The fields of |tbs_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der_| subtracted by |tag_len_pos|
  // equates to the size of the value of |tbs_certificate|.
  EncodeTagAndLength(0x30, der_.size() - tag_len_pos, tag_len_pos, der_);
}

void CertToDER::Encode(const asn1_pdu::PDU& pdu) {
  // Used to encode PDU's for fields that contain them.
  std::vector<uint8_t> der_pdu = pdu_to_der.PDUToDER(pdu);
  der_.insert(der_.end(), der_pdu.begin(), der_pdu.end());
}

template <typename T>
void CertToDER::Encode(const T& t) {
  if (t.has_pdu()) {
    Encode(t.pdu());
    return;
  }
  Encode(t.value());
}

std::vector<uint8_t> CertToDER::X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  // Reset the previous state.
  der_.clear();

  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der_.size();

  Encode(X509_certificate.tbs_certificate());
  Encode(X509_certificate.signature_algorithm());
  Encode(X509_certificate.signature_value());

  // The fields of |X509_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der_| subtracted by |tag_len_pos|
  // equates to the size of the value of |X509_certificate|.
  EncodeTagAndLength(0x30, der_.size() - tag_len_pos, tag_len_pos, der_);
  return der_;
}

}  // namespace x509_certificate