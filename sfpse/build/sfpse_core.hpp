#pragma once

#include "rocksdb_wrapper.hpp"
#include "logger.hpp"

#include <string>
#include <array>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <stdio.h>

#include <ssdmap/bucket_map.hpp>
#include <sse/crypto/hmac.hpp>
#include <sse/crypto/hash.hpp>



using std::string;
namespace sse {
namespace sfpse {

typedef sse::crypto::HMac<crypto::Hash> HMAC_SHA512;

constexpr size_t kDerivationKeySize = 32;
constexpr size_t symKeySize = 32;
constexpr size_t BLKidSize = 32;
//typedef std::array<uint8_t, BLKidSize> search_token_type;
typedef std::string search_token_type;
typedef std::string update_token_type;
//typedef std::array<uint8_t, BLKidSize> update_token_type;
enum op{del,add};
//constexpr size_t kUpdateTokenSize = 16;

//typedef std::array<uint8_t, kSearchTokenSize> search_token_type;
//typedef std::array<uint8_t, kUpdateTokenSize> update_token_type;
typedef uint64_t index_type;
extern string old_str;
extern string new_str;
/*struct TokenHasher
{
public:
    size_t operator()(const update_token_type& ut) const;
};*/

struct SearchRequest
{
	search_token_type id;
    string key;
    SearchRequest(){

    }
    SearchRequest(const search_token_type& id_,const string& key_){
		id = id_;
		key = key_;
	}
};


struct UpdateRequest
{
public:
	update_token_type id;
	string value;
	UpdateRequest(){

	}
	UpdateRequest(const update_token_type& id_,const string& value_){
		id = id_;
		value = value_;
	}
};
class Kbbc{
	public:
		Kbbc();
		Kbbc(const update_token_type& _id,const string& _value);
		Kbbc(const string& _blk_id,const string& _blk_key,const string& _blk_value,const string& _blk_ptr);
		void encrypt_blk(string& KEY);
		void decrypt_blk(string& KEY);
		void setId(const update_token_type& _id){
			id = _id;
		}
		string get_blkKey() const;
		string get_blkValue() const;
		string get_blkPtr() const;
		string value;
		string blk_id;
		string blk_key;
		string blk_value;
		string blk_ptr;
		update_token_type id;
	private:
	};
class SfpseClient_core {
public:
	SfpseClient_core(bool defaul_value, const std::string& key_dir_path, const std::string& indice_dir_path);
	SfpseClient_core(const std::string& derivation_master_key,const std::string& keyword_indexer_path);
	//SfpseClient_core();
    virtual ~SfpseClient_core();

    const std::string derivation_master_key() const;
    virtual void write_keys(std::string dir_path) const;
    virtual void mk_indicesFile(std:: string dir_path);

    virtual UpdateRequest  update_request(const op opcode,std::string keyword, const index_type index);
    virtual SearchRequest   search_request(const std::string &keyword) const;

    // Warning : temp to put there
    std::ofstream sfpse_log;


private:
    HMAC_SHA512 hmac;
    std::map<std::string,std::pair<std::string,std::string>> keyword_indices_;
    std::fstream keyword_indexer_stream_;

    void load_keyword_indices(const std::string &path);
};

class SfpseServer {
public:
	SfpseServer(const std::string& db_path);

    std::list<index_type> search(const SearchRequest& req);
    //void gen_search_token(const SearchRequest& req);
    void update(UpdateRequest req);
    clock_t db_time;

    //std::ostream& print_stats(std::ostream& out) const;

private:
//    ssdmap::bucket_map<update_token_type, index_type, TokenHasher> edb_;
    string blk_nullptr;
	sse::sophos::RockDBWrapper edb_;

};

}
}
