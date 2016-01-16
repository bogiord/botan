/*
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests : public Text_Based_Test
   {
   public:
      HMAC_DRBG_Tests() : Text_Based_Test("hmac_drbg.vec",
                                          {"EntropyInput",
                                           "EntropyInputReseed",
                                           "Out"},

                                          {"AdditionalInput1",
                                           "AdditionalInput2"}) {}

      Test::Result run_one_test(const std::string& hmac_hash, const VarMap& vars) override
         {
         const std::vector<byte> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<byte> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<byte> expected     = get_req_bin(vars, "Out");

         const std::vector<byte> addl_data1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<byte> addl_data2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + hmac_hash + ")");

         std::unique_ptr<Botan::HMAC_DRBG> drbg;
         try
            {
            drbg.reset(new Botan::HMAC_DRBG(hmac_hash));
            }
         catch(Botan::Lookup_Error&)
            {
            return result;
            }

         Botan::Entropy_Sources srcs;
         std::unique_ptr<Botan::Entropy_Source> src(new Fixed_Output_Entropy_Source(seed_input, reseed_input));
         srcs.add_source(std::move(src));

         // seed
         drbg->reseed_with_sources(srcs, 0, std::chrono::milliseconds(100));

         // reseed
         drbg->reseed_with_sources(srcs, 0, std::chrono::milliseconds(100));

         Botan::secure_vector<byte> output(expected.size());

         // discard first block
         drbg->randomize_with_input(output.data(), output.size(),
                                    addl_data1.data(), addl_data1.size());

         // check second block
         drbg->randomize_with_input(output.data(), output.size(),
                                    addl_data2.data(), addl_data2.size());

         result.test_eq("rng", output, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("hmac_drbg", HMAC_DRBG_Tests);

#endif

}

}
