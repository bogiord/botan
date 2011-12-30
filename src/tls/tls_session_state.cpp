/*
* TLS Session Management
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session_state.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_str.h>
#include <botan/time.h>

namespace Botan {

TLS_Session_Params::TLS_Session_Params(const MemoryRegion<byte>& session_identifier,
                                       const MemoryRegion<byte>& master_secret,
                                       Version_Code version,
                                       u16bit ciphersuite,
                                       byte compression_method,
                                       Connection_Side side,
                                       bool secure_renegotiation_supported,
                                       size_t fragment_size,
                                       const std::vector<X509_Certificate>& certs,
                                       const std::string& sni_hostname,
                                       const std::string& srp_identifier) :
   m_start_time(system_time()),
   m_identifier(session_identifier),
   m_master_secret(master_secret),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_compression_method(compression_method),
   m_connection_side(side),
   m_secure_renegotiation_supported(secure_renegotiation_supported),
   m_fragment_size(fragment_size),
   m_sni_hostname(sni_hostname),
   m_srp_identifier(srp_identifier)
   {
   // FIXME: encode all of them?
   if(certs.size())
      m_peer_certificate = certs[0].BER_encode();
   }

TLS_Session_Params::TLS_Session_Params(const byte ber[], size_t ber_len)
   {
   BER_Decoder decoder(ber, ber_len);

   byte side_code = 0;
   ASN1_String sni_hostname_str;
   ASN1_String srp_identifier_str;

   BER_Decoder(ber, ber_len)
      .decode_and_check(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION),
                        "Unknown version in session structure")
      .decode(m_identifier, OCTET_STRING)
      .decode_integer_type(m_start_time)
      .decode_integer_type(m_version)
      .decode_integer_type(m_ciphersuite)
      .decode_integer_type(m_compression_method)
      .decode_integer_type(side_code)
      .decode_integer_type(m_fragment_size)
      .decode(m_secure_renegotiation_supported)
      .decode(m_master_secret, OCTET_STRING)
      .decode(m_peer_certificate, OCTET_STRING)
      .decode(sni_hostname_str)
      .decode(srp_identifier_str);

   m_sni_hostname = sni_hostname_str.value();
   m_srp_identifier = srp_identifier_str.value();
   m_connection_side = static_cast<Connection_Side>(side_code);
   }

SecureVector<byte> TLS_Session_Params::BER_encode() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(m_identifier, OCTET_STRING)
         .encode(static_cast<size_t>(m_start_time))
         .encode(static_cast<size_t>(m_version))
         .encode(static_cast<size_t>(m_ciphersuite))
         .encode(static_cast<size_t>(m_compression_method))
         .encode(static_cast<size_t>(m_connection_side))
         .encode(static_cast<size_t>(m_fragment_size))
         .encode(m_secure_renegotiation_supported)
         .encode(m_master_secret, OCTET_STRING)
         .encode(m_peer_certificate, OCTET_STRING)
         .encode(ASN1_String(m_sni_hostname, UTF8_STRING))
         .encode(ASN1_String(m_srp_identifier, UTF8_STRING))
      .end_cons()
   .get_contents();
   }

bool TLS_Session_Manager_In_Memory::find(const MemoryVector<byte>& session_id,
                                         TLS_Session_Params& params)
   {
   std::map<std::string, TLS_Session_Params>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i == sessions.end())
      return false;

   // session has expired, remove it
   const u64bit now = system_time();
   if(i->second.start_time() + session_lifetime >= now)
      {
      sessions.erase(i);
      return false;
      }

   params = i->second;
   return true;
   }

void TLS_Session_Manager_In_Memory::prohibit_resumption(
   const MemoryVector<byte>& session_id)
   {
   std::map<std::string, TLS_Session_Params>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i != sessions.end())
      sessions.erase(i);
   }

void TLS_Session_Manager_In_Memory::save(const TLS_Session_Params& session_data)
   {
   if(max_sessions != 0)
      {
      /*
      This removes randomly based on ordering of session ids.
      Instead, remove oldest first?
      */
      while(sessions.size() >= max_sessions)
         sessions.erase(sessions.begin());
      }

   sessions[hex_encode(session_data.session_id())] = session_data;
   }

}
