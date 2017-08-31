#include "sfpse_core.hpp"
#include "sfpse_utils.hpp"

#include "utils.hpp"
#include "logger.hpp"
#include "thread_pool.hpp"

#include <sse/crypto/cipher.hpp>
#include <sse/crypto/hmac.hpp>
#include <sse/crypto/hash.hpp>

#include <assert.h>
#include <iostream>
#include <algorithm>
#include <array>
#include <unistd.h>
#include <stdio.h>
#include <map>

namespace sse {
namespace sfpse {

string old_str;
string new_str;

Kbbc::Kbbc(){
	/*blk_id.clear();
	blk_value.clear();
	blk_key.clear();
	blk_ptr.clear();
	value.clear();*/
}
Kbbc::Kbbc(const string& _blk_id,const string& _blk_key,const string& _blk_value,const string& _blk_ptr){
	blk_id = _blk_id;
	blk_key = _blk_key;
	blk_value = _blk_value;
	blk_ptr = _blk_ptr;
}
Kbbc::Kbbc(const update_token_type& _id,const string& _value){
	id = _id;
	value = _value;
}
void Kbbc::encrypt_blk(string& KEY){
	assert(KEY.length()==symKeySize);
	std::array<uint8_t, BLKidSize> p;
	std::copy(KEY.begin(), KEY.end(), p.data());
	sse::crypto::Cipher cipher(p);
	string in_enc = blk_key+blk_ptr+blk_value;
	assert(!in_enc.empty());
	string out_enc;
	cipher.encrypt(in_enc, out_enc);
	value = string(out_enc);
}
void Kbbc::decrypt_blk(string& KEY){
	assert(KEY.length()==symKeySize);
	std::array<uint8_t, BLKidSize> p;
	std::copy(KEY.begin(), KEY.end(), p.data());
	sse::crypto::Cipher cipher(p);
	string in_dec = value;
	assert(!in_dec.empty());
	string out_dec;
	cipher.decrypt(in_dec, out_dec);
	out_dec = string(out_dec);
	blk_key = out_dec.substr(0,symKeySize);
	blk_ptr = out_dec.substr(BLKidSize,symKeySize);
	blk_value = out_dec.substr(BLKidSize*2);
	//std::cout<<"blk_value:\t"<<blk_value<<std::endl;
}
string Kbbc::get_blkKey() const{
	return blk_key;
}
string Kbbc::get_blkValue() const{
	return blk_value;
}
string Kbbc::get_blkPtr() const{
	return blk_ptr;
}

SfpseServer::SfpseServer(const std::string& db_path):edb_(db_path)
{
	std::array<uint8_t,symKeySize> k;
	k.fill(0x00);
	blk_nullptr = string(k.begin(),k.end());
	db_time = clock_t(0);
}
SfpseClient_core::SfpseClient_core(bool defaul_value, const std::string& key_dir_path, const std::string& indice_dir_path) :hmac(HMAC_SHA512())
{
	/*string log_file;
		char* buffer;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			log_file = string(buffer)+"/logfile";
		}

		sfpse_log.open(log_file,std::ios_base::binary);
		if(!sfpse_log.is_open())
			perror("log file open error");*/
	if(defaul_value){
		write_keys(string());
		mk_indicesFile(string());
	}else{
		write_keys(key_dir_path+ "/client.sav");
		mk_indicesFile(indice_dir_path);
	}

	keyword_indices_.clear();

}
SfpseClient_core::SfpseClient_core(const std::string& derivation_master_key_string,const std::string& keyword_indexer_path) : hmac(HMAC_SHA512(derivation_master_key_string))
{
	/*string log_file;
		char* buffer;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			log_file = string(buffer)+"/logfile";
		}

		sfpse_log.open(log_file,std::ios_base::binary);
		if(!sfpse_log.is_open())
			perror("log file open error");*/
	keyword_indices_.clear();
	load_keyword_indices(keyword_indexer_path);
}
void SfpseClient_core::load_keyword_indices(const std::string &path){
	keyword_indexer_stream_.open(path,std::ios_base::in|std::ios_base::binary);
	if (!keyword_indexer_stream_.is_open()) {
		keyword_indexer_stream_.close();
		throw std::runtime_error("Could not open keyword index file " + path);
	}
	std::string line, kw, id,key;
	//sfpse_log<<"load back to files"<<std::endl;
	char buffer[BLKidSize+1];
	while(keyword_indexer_stream_.read(buffer,BLKidSize)){
		key = string(buffer,buffer+BLKidSize);
		if(keyword_indexer_stream_.read(buffer,BLKidSize)){
			id = string(buffer,buffer+BLKidSize);
		}else{
			//sfpse_log<<"id:\t"<<hex_string(id)<<"\nkey:\t"<<hex_string(key)<<std::endl;
			throw std::runtime_error("parse index fails" );
		}
		if(!std::getline(keyword_indexer_stream_, kw, '\n'))
		{
			throw std::runtime_error("parse index fails!" );
		}
		keyword_indices_.insert(std::make_pair(kw,make_pair(id,key)));
		//sfpse_log<<"key:\t"<<hex_string(key)<<"\nid:\t"<<hex_string(id)<<"\nkw:\t"<<hex_string(kw)<<std::endl;
	}
	/*std::remove(path.c_str());
	keyword_indexer_stream_.open(path,std::ios_base::in);
	if (!keyword_indexer_stream_.is_open()) {
		keyword_indexer_stream_.close();
		throw std::runtime_error("Could not open keyword index file " + path);
	}*/
}
SfpseClient_core::~SfpseClient_core(){
	if (!keyword_indexer_stream_.is_open()) {
		keyword_indexer_stream_.close();
		throw std::runtime_error("Could not open keyword index file");
	}
	//sfpse_log<<"write back to files"<<std::endl;
	for(auto it = keyword_indices_.begin(); it!= keyword_indices_.end();++it){
		//sfpse_log<<"key:\t"<<hex_string(it->second.second)<<"\nid:\t"<<hex_string(it->second.first)<<"\nkw:\t"<<hex_string(it->first)<<std::endl;
			keyword_indexer_stream_<<it->second.second<<it->second.first<<it->first<<std::endl;

		}
	keyword_indexer_stream_.close();
}
const std::string SfpseClient_core::derivation_master_key() const{
	return std::string(hmac.key().begin(), hmac.key().end());
}
void SfpseClient_core::write_keys(std::string dir_path) const{
	if(dir_path.empty()){
		 char *buffer;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			dir_path = string(buffer)+"/client.sav";
			free(buffer);
		}
	}
	if (!is_directory(dir_path)) {
		mkdir(dir_path.c_str(),0700);
	}

	std::string master_key_path = dir_path + "/uk.key";

	std::ofstream master_key_out(master_key_path.c_str());
	if (!master_key_out.is_open()) {
		throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
	}

	master_key_out << derivation_master_key();
	master_key_out.close();
}
void SfpseClient_core::mk_indicesFile(std::string dir_path){
	if(dir_path.empty()){
		 char *buffer;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			dir_path = string(buffer)+"/client.sav";
			free(buffer);
		}
	}
	if (!is_directory(dir_path)) {
		mkdir(dir_path.c_str(),0700);
	}

	std::string keyword_indices_path = dir_path + "/indices.dat";

	keyword_indexer_stream_.open(keyword_indices_path.c_str(), std::ios_base::app | std::ios_base::out);
	if (!keyword_indexer_stream_.is_open()) {
		keyword_indexer_stream_.close();
		throw std::runtime_error("Could not open keyword index file " + keyword_indices_path);
	}
}

UpdateRequest  SfpseClient_core::update_request(const op opcode,std::string keyword, const index_type index){
	string r = gen_random_string(symKeySize);
	std::array<uint8_t,64> hmac_id = hmac.hmac(r);
	//std::array<uint8_t,BLKidSize> id;
	//std::memcpy(id.data(),hmac_id.data(),BLKidSize);
	string blk_id = string(hmac_id.begin(),hmac_id.begin()+32);
	string blk_key = gen_random_string(symKeySize);
	string blk_value = std::to_string((index<<1)+opcode);
	Kbbc* new_blk;
	auto it = keyword_indices_.find(keyword);
	if (it == keyword_indices_.end()) {//new keyword
		keyword_indices_.insert(std::map<string,std::pair<string,string>>::value_type(keyword,std::make_pair(blk_id,blk_key)));
		std::array<uint8_t,symKeySize> k;
		k.fill(0x00);
		string blk_none = string(k.begin(),k.end());
		new_blk = new Kbbc(blk_id,blk_none,blk_value,blk_none);

	}else{
		new_blk = new Kbbc(blk_id,keyword_indices_[keyword].second,blk_value,keyword_indices_[keyword].first);
		keyword_indices_[keyword] = std::make_pair(blk_id,blk_key);
	}
	new_blk->encrypt_blk(blk_key);
	UpdateRequest rs(blk_id,new_blk->value);
	return rs;
}
SearchRequest   SfpseClient_core::search_request(const std::string &keyword) const{
	auto it = keyword_indices_.find(keyword);
	SearchRequest req;
	if (it == keyword_indices_.end()) {//new keyword
		throw std::runtime_error("keyword not be found!\n");
	}else{
		req.id = it->second.first;
		req.key = it->second.second;
	}
	return req;
}
void SfpseServer::update(UpdateRequest req){
	clock_t  start, end;
	start  = clock();
	edb_.put(req.id, req.value);
	end = clock();
	db_time += (end-start);

}
std::list<index_type> SfpseServer::search(const SearchRequest& req){
	std::list<index_type> result;

	string r;
	Kbbc new_blk;
	new_blk.blk_ptr = req.id;
	new_blk.blk_key = req.key;

	std::map<index_type,int> merge;
	op opcode;
	index_type index;

	int count =0;
	do{
		clock_t  start, end;
		start  = clock();
		edb_.get(new_blk.blk_ptr,new_blk.value);
		end = clock();
		db_time += (end-start);
		//new_blk.value = r;
		new_blk.decrypt_blk(new_blk.blk_key);
		index = std::stoull(new_blk.blk_value);
		opcode = (op)(index&1);
		/*if(opcode == del){
			if(merge.find(index>>1)==merge.end()){
				merge[index>>1] = -1;
			}else{
				merge[index>>1]--;
			}
		}else{
			if(merge.find(index>>1)==merge.end()){
				merge[index>>1] = 1;
			}else{
				merge[index>>1]++;
			}
		}*/
		//std::cout<<"fetch block id:\t"<<hex_string(id)<<"\nvalue\t"<<hex_string(new_blk.value)<<std::endl;
		//id = new_blk.blk_ptr;
		//key = new_blk.blk_key;
		result.push_back((index>>1));
	}while(new_blk.blk_ptr!=blk_nullptr);
	/*for(auto it=merge.begin();it!=merge.end();++it){
		if((it->second)<0){
			throw std::runtime_error("search operation fails!\n");
		}
		if((it->second)>0)
			result.push_back(it->first);
	}*/
	return result;
}

}
}
