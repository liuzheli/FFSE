#include "sfpse_utils.hpp"
#include <sse/crypto/prg.hpp>
#include <sse/crypto/random.hpp>

#include <array>

std::string gen_random_string(size_t len){
	 std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
	 sse::crypto::random_bytes(k);
	 sse::crypto::Prg prg(k);
	 return prg.derive(32);
}
