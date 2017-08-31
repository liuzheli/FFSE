#include "sfpse_core.hpp"
#include "sfpse_utils.hpp"
#include "utils.hpp"

#include <iostream>
#include <array>
#include <unistd.h>
#include <memory>
#include <sse/crypto/cipher.hpp>
#include <sse/crypto/hmac.hpp>
#include <sse/crypto/tdp.hpp>

using namespace sse::sfpse;
using std::endl;
using std::cout;

double getrate(size_t n){
	double rate=  1;
	while(n>100){
		rate = rate*0.4;
		n = n/10;
	}
	return rate*0.3;
}
void test_rate(){
	size_t base = 10;
	size_t num = 100;
	for(int i=2;i<7;i++){
		cout<<"num:\t"<<num<<"\trate:\t"<<getrate(num)<<endl;
		num = num*base;
	}
}
void test_blk(){
	/*string KEY = gen_random_string(symKeySize);
	Kbbc test_blk("a","a","a","a");
	test_blk.encrypt_blk(KEY);

	Kbbc test_blk2("a","a","a","a");
	test_blk2.encrypt_blk(KEY);*/


	/*string KEY = gen_random_string(symKeySize);
	std::array<uint8_t, BLKidSize> p;
	std::copy(KEY.begin(), KEY.end(), p.data());
	sse::crypto::Cipher cipher(p);
	string in_enc = gen_random_string(symKeySize);
	string out_enc;
	cipher.encrypt(in_enc, out_enc);*/

	/*char buffer[32];
	for(int i=0;i<32;i++)
		buffer[i] = '4';
	Kbbc test_blk;
	test_blk.blk_value = gen_random_string(symKeySize);
	string KEY = gen_random_string(symKeySize);


	for(int i=0;i<1000;i++){
		test_blk.encrypt_blk(KEY);
	}

	cout<<"KBBC encrypted time: \t "<<(end-start)<<"\tms\n";*/
	/*string a;
	clock_t  start, end;
	start  = clock();
	for(int i=0;i<1000;i++){
		a= gen_random_string(symKeySize);
	}
	end = clock();
	cout<<"random string time: \t "<<(end-start)<<"\tms\n";*/

	clock_t  start, end;
	sse::crypto::TdpInverse tdp_inv;
	string pk = tdp_inv.public_key();
	sse::crypto::Tdp tdp(pk);
	string sample = tdp_inv.sample();
	string goal, v;
	goal = tdp_inv.invert_mult(sample, 1000);
	v = sample;
	for (size_t j = 0; j < 1000; j++) {
		v = tdp_inv.invert(v);
	}
	start  = clock();
	for (size_t j = 0; j < 1000; j++) {
		v = tdp.eval(v);
	}
	end = clock();
	cout<<"Tdp implemented in RSA: \t "<<(end-start)<<"\tms\n";

	/*sse::sfpse::HMAC_SHA512 hmac;
	string r =gen_random_string(symKeySize);

	clock_t  start, end;
	start  = clock();
	for(int i=0;i<1000;i++){
		std::array<uint8_t,64> hmac_id = hmac.hmac(r);
			string blk_id = string(hmac_id.begin(),hmac_id.begin()+32);
	}
	end = clock();
	cout<<"random string time: \t "<<(end-start)<<"\tms\n";
*/


}
void test_prg(){
	 std::string out1 = gen_random_string(32);
	  cout<<"random string out1 " <<out1 <<endl;
	  cout<<"length " <<out1.length()<<endl;

}
void test_main(){
	std::unique_ptr<SfpseClient_core> client;
	SfpseServer server("server.dat");
	string client_master_key_path;
	string client_kw_indices_path;
	char *buffer;
	if((buffer = getcwd(NULL, 0)) == NULL)
	{
		perror("getcwd error");
	}
	else
	{
		client_master_key_path = string(buffer)+"/client.sav/uk.key";
		client_kw_indices_path = string(buffer)+"/client.sav/indices.dat";
		free(buffer);
	}
	std::ifstream client_master_key_in(client_master_key_path.c_str());

	if (client_master_key_in.good() == true) {
		std::stringstream client_master_key_buf;
		cout << "Restart client's master key and keyword indices file" << endl;
		client_master_key_buf << client_master_key_in.rdbuf();
		client.reset(new SfpseClient_core(client_master_key_buf.str(),client_kw_indices_path));
	}else{
		cout << "Create new client's key and keyword indices file" << endl;
		client.reset(new SfpseClient_core(true,string(),string()));
	}
	//std::cout<<"load search result\n";
	string input_file;
	if((buffer = getcwd(NULL, 0)) == NULL)
	{
		perror("getcwd error");
	}
	else
	{
		std::string parPath = string(buffer) + "/cmp_bench/dataset/"+std::to_string(10);
		input_file = parPath +"/pair"+std::to_string(2)+".data\n";
	}
	std::ifstream fin(input_file);
	if(!fin.is_open()){
		perror("data files can not open");
	}
	string tmp_kw;
	size_t tmp_ind;
	UpdateRequest u_req;
	    SearchRequest s_req;
	    std::list<index_type> res;
	/*while (!fin.eof())
	{
	   fin>>tmp_kw;
	   fin>>tmp_ind;
	   u_req = client->update_request(add, tmp_kw,tmp_ind);
	   server.update(u_req);
	 }
	for(index_type i=1;i<=2;i++){
			UpdateRequest u_req = client->update_request(add,"toto", i);
			server.update(u_req);
		}
	fin.close();
	fin.open(input_file);*/
	if(!fin.is_open()){
		perror("data files can not open 2");
	}
	while (!fin.eof())
	{
	   fin>>tmp_kw;
	   fin>>tmp_ind;
	   //server.sfpse_log<<"search keyword:\t"<<tmp_kw<<"\n";
	   client->sfpse_log<<"search keyword:\t"<<tmp_kw<<"\n";
	  /* if(kw_count %100 == 0)
		   sse::logger::log(sse::logger::INFO) << "kw_count  "<<(kw_count)  << std::endl;*/
	   s_req = client->search_request(tmp_kw);
	   server.search(s_req);
	 }
	/*SearchRequest s_req = client->search_request("toto");
		std::list<index_type> result = server.search(s_req);
		for(auto it = result.begin();it!=result.end();++it){
			cout<<(*it)<<"\t";
		}
		cout<<endl;*/
	/*for(index_type i=1;i<=2;i++){
		UpdateRequest u_req = client->update_request(del,"toto", i);
		server.update(u_req);
	}*/
	//string blk_id = string(u_req.id.begin(),u_req.id.end());
	//cout<<"insert value\n id: "<<hex_string(blk_id)<<"\n fetch value:  "<<u_req.value<<endl;*/
	/*auto it = client->keyword_indices_.begin();
	cout<<"see the map\n";
	cout<<"kw:\t"<<it->first<<endl;
	cout<<"id: \t"<<hex_string(it->second.first)<<endl;
	cout<<"key:\t"<<hex_string(it->second.second)<<endl;*/
	/*std::cout<<"update search result\n";
	 s_req = client->search_request("toto");
	result = server.search(s_req);*/
	/*for(auto it = result.begin();it!=result.end();++it){
		cout<<(*it)<<"\t";
	}
	cout<<endl;*/


}
int main(int argc, const char * argv[]) {
	test_blk();
	/*for(int i=0;i<10 ;i++)
		test_prg();*/
	//test_blk();
	//test_main();
	//test_rate();
    return 0;
}
