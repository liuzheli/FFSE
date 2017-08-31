#include "src/logger.hpp"
#include "src/sfpse_core.hpp"
#include "src/sfpse_utils.hpp"
#include "src/utils.hpp"

#include <sse/crypto/utils.hpp>

#include       <time.h>
#include <memory>
#include <mutex>
#include <fstream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include <unistd.h>
using std::string;
using std::ifstream;
using std::ofstream;
using std::cout;
using std::endl;
using namespace sse::sfpse;
/*
 * parse command line
 */
double getrate(size_t n){
	double rate=  1;
	while(n>100){
		rate = rate*0.4;
		n = n/10;
	}
	return rate*0.3;
}
int main(int argc, char** argv) {
    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_client.out");

    sse::crypto::init_crypto_lib();

    opterr = 0;
    int c;
    char bench_code = ' ';// u for update; s for search; t for token generation
    char token_bench_code = ' '; // u for update token generation; t for search token generation

    string input_file;
    string keyword_file;
    //input_file = "/home/sfpse/sophos/cmp_bench/dataset/client_tmp.data";
    //keyword_file = "/home/sfpse/sophos/cmp_bench/dataset/client_tmp.keyword";
    std::list<std::string> keywords;
    std::string client_db;
    std::string output_path;
    size_t rnd_entries_count = 0;
    size_t bench_num = -1;

    while ((c = getopt (argc, argv, "t:d:r:n:")) != -1)
        switch (c)
    {
        case 't':
        	bench_code = std::string(optarg).c_str()[0];
        	break;
        case 'd':
            token_bench_code = std::string(optarg).c_str()[0];
        	break;
        case 'r':
            rnd_entries_count = (uint32_t)std::stod(std::string(optarg),nullptr);
            break;
        case 'n':
        	//std::cout<<string(optarg)<<std::endl;
        	bench_num = (uint32_t)std::stoi(std::string(optarg),nullptr);
        	break;
        case '?':
            if (optopt == 't'||optopt == 'd'||optopt == 'r')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            exit(-1);
    }
    string client_master_key_path;
    string client_kw_indices_path;

    std::unique_ptr<SfpseClient_core> client;
    UpdateRequest u_req;
    SearchRequest s_req;
    std::list<index_type> res;
    string key;

    if(rnd_entries_count!=0 && bench_num>= 0 && bench_code == 'u'){
    	char *buffer;
    	string parPath;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			parPath = string(buffer) + "/cmp_bench/dataset/"+std::to_string(rnd_entries_count);
			input_file = parPath +"/pair"+std::to_string(bench_num)+".data\n";
		}
    	ifstream fin(input_file);
    	if(!fin.is_open()){
    		perror("data files can not open");
    	}
    	string tmp_kw;
    	size_t tmp_ind;
    	cout << "Create new client-server instances" << std::endl;
    	string clientPath = parPath + "/pair"+std::to_string(bench_num);
    	std::system(string("rm -r "+clientPath).c_str());
    	mkdir(clientPath.c_str(),0700);
    	clientPath = clientPath + "/";
    	client.reset(new SfpseClient_core(false,clientPath, clientPath));

    	SfpseServer server(clientPath+"server.dat");

    	string reportPath = string(buffer) + "/report.csv";
    	std::ofstream report;
    	report.open(reportPath,std::ios_base::app);
        clock_t  start, end;
        sse::logger::log(sse::logger::INFO) << std::dec<< rnd_entries_count<<std::endl;
    	sse::logger::log(sse::logger::INFO) << "-------------- Update benchmark starting --------------" << std::endl;
    	/*fin>>tmp_kw;
    	fin>>tmp_ind;
    	int listnum = 500;
    	int app = 0;
    	int CT = 75;
		for(int i=1;i<listnum;i++){
			app = (app+1)%CT;
			if(i%50==0){
		    	start  = clock();
				u_req = client->update_request(add, tmp_kw,tmp_ind);
				end = clock();
				report<<"listnum\t"<<i<<"\t"<<(end-start)<<"\n";
				    	std::cout<<"listnum\t"<<i<<"\t"<<(end-start)+app*4<<"\n";
			}else{
				u_req = client->update_request(add, tmp_kw,tmp_ind);
			}

		}
    	u_req = client->update_request(add, tmp_kw,tmp_ind);*/

    	/*while (!fin.eof())
    	{
    	  fin>>tmp_kw;
    	  fin>>tmp_ind;
    	  u_req = client->update_request(add, tmp_kw,tmp_ind);
    	  server.update(u_req);
    	}*/

    	sse::logger::log(sse::logger::INFO) << "-------------- Update benchmark Report --------------" << std::endl;
    	//sse::logger::log(sse::logger::INFO) << std::dec<< "updating "<<(14*rnd_entries_count) <<" <keyword index> pair in empty rocksdb spending " <<(end-start)<<" ms"<< std::endl;
    	/*report<<"listnum\t"<<listnum<<"\t"<<(end-start)<<"\n";
    	    	std::cout<<"listnum\t"<<listnum<<"\t"<<(end-start)<<"\n";*/
    	/*sse::logger::log(sse::logger::INFO) << "db_operation time:\t"<<server.db_time<<std::endl;
		report<<"db_consume\t"<<(server.db_time)<<"\n";
		sse::logger::log(sse::logger::INFO) << "pure update operation time:\t"<<((end-start) -server.db_time)<<std::endl;
		report<<"pureUpdate\t"<<((end-start) -server.db_time)<<"\n";*/
    	report.close();
    	fin.close();
    }else if(rnd_entries_count!=0 && bench_num>= 0 && bench_code == 's'){
    	char *buffer;
		string parPath;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			parPath = string(buffer) + "/cmp_bench/dataset/"+std::to_string(rnd_entries_count);
			input_file = parPath +"/pair"+std::to_string(bench_num)+".data\n";
		}
		//cout<<"input file:\t"<<input_file<<endl;
		ifstream fin(input_file);
		if(!fin.is_open()){
			perror("data files can not open");
		}
		string tmp_kw;
		size_t tmp_ind;
		cout << "Create new client-server instances" << std::endl;
		string clientPath = parPath + "/pair"+std::to_string(bench_num);
		std::system(string("rm -r "+clientPath).c_str());
		mkdir(clientPath.c_str(),0700);
		clientPath = clientPath + "/";
		client.reset(new SfpseClient_core(false,clientPath, clientPath));

		SfpseServer server(clientPath+"server.dat");

		string reportPath = string(buffer) + "/report.csv";
		std::ofstream report;
		report.open(reportPath,std::ios_base::app);
		int count =0;
		clock_t  start, end;


		while (!fin.eof())
		{

			count++;
			if(count == 10000){
				server.db_time = 0;
				start  = clock();
						for(int i=0;i<10;i++){
							 fin>>tmp_kw;
							 fin>>tmp_ind;
							 u_req = client->update_request(add, tmp_kw,tmp_ind);
							 server.update(u_req);

						}
						end = clock();
						std::cout << "average pure update:\t"<<((end - start-server.db_time)/10) <<std::endl;
			}
		  fin>>tmp_kw;
		  fin>>tmp_ind;
		  u_req = client->update_request(add, tmp_kw,tmp_ind);
		  server.update(u_req);
		}
		sse::logger::log(sse::logger::INFO) << "-------------- database setup complete --------------" << std::endl;
		fin.close();
		fin.open(input_file.c_str());
		if(!fin.is_open()){
			perror("data files can not open");
		}
		server.db_time = 0;
		sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Starting --------------" << std::endl;

		size_t threshold = 14*rnd_entries_count*getrate(rnd_entries_count);
		//sse::logger::log(sse::logger::INFO) << "threshold  "<<(threshold)  << std::endl;
		int kw_count = 0;
		server.db_time = 0;
		start  = clock();
		for(int i=0;i<10;i++){
			fin>>tmp_kw;
			fin>>tmp_ind;
			s_req = client->search_request(tmp_kw);
			server.search(s_req);
			cout<<"\nending one search\n";
		}
		end = clock();
		std::cout << "\npure average search:\t"<<(end-start-server.db_time)/10 <<std::endl;






		/*start  = clock();
		std::cout << "server side:\t"<<(start - end) <<std::endl;
		std::cout << "pure server side:\t"<<(start - end-server.db_time) <<std::endl;*/
		/*while (!fin.eof()&&kw_count<threshold)
		{
		   fin>>tmp_kw;
		   fin>>tmp_ind;
		   kw_count++;
		   if(kw_count %100 == 0)
			   sse::logger::log(sse::logger::INFO) << "kw_count  "<<(kw_count)  << std::endl;
		   s_req = client->search_request(tmp_kw);
		   server.search(s_req);
		 }*/
		//end = clock();
		/*sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Report --------------" << std::endl;
		sse::logger::log(sse::logger::INFO) << std::dec<< "searching "<<(threshold) <<" <keyword in rocksdb " <<(end-start)<<" ms"<< std::endl;
		sse::logger::log(sse::logger::INFO) << std::dec<< "db_operation time:\t"<<server.db_time<<endl;
		report<<"search\t"<<(threshold)<<"\t"<<(end-start)<<"\tdatabase\t"<<14*rnd_entries_count<<"\n";
		report<<"db_consume\t"<<(server.db_time)<<"\n";
		sse::logger::log(sse::logger::INFO) << "pure search operation time:\t"<<((end-start) -server.db_time)<<std::endl;
		report<<"pureSearch\t"<<((end-start) -server.db_time)<<"\n";*/
		report.close();
		fin.close();
		//std::system(string("rm -r "+clientPath).c_str());
    	/*char *buffer;
		string parPath;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			parPath = string(buffer) + "/cmp_bench/dataset/"+std::to_string(rnd_entries_count);
			input_file = parPath +"/pair"+std::to_string(bench_num)+".data\n";
		}
		string clientPath = parPath + "/pair"+std::to_string(bench_num);
		clientPath = clientPath + "/";

		client_master_key_path = clientPath+"uk.key";
		client_kw_indices_path = clientPath+"indices.dat";

		string reportPath = string(buffer) + "/report.csv";
		std::ofstream report;
		report.open(reportPath,std::ios_base::app);

		std::ifstream client_master_key_in(client_master_key_path.c_str());

		if(client_master_key_in.good() != true)
		{
			client_master_key_in.close();

			throw std::runtime_error("All streams are not in the same state");
		}

        if (client_master_key_in.good() == true) {
        	std::stringstream client_master_key_buf;
			std::cout << "Restart client's master key and keyword indices file" << std::endl;
			client_master_key_buf << client_master_key_in.rdbuf();
			client.reset(new SfpseClient_core(client_master_key_buf.str(),client_kw_indices_path));
			SfpseServer server(clientPath+"server.dat");

            ifstream fin(input_file);
            if(!fin.is_open()){
				perror("data files can not open");
			}
            string tmp_kw;
            size_t tmp_ind;
            int kw_count=0;
            sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Starting --------------" << std::endl;
            clock_t  start, end;
            size_t threshold = 14*rnd_entries_count*getrate(rnd_entries_count);
            //sse::logger::log(sse::logger::INFO) << "threshold  "<<(threshold)  << std::endl;
            start  = clock();
            while (!fin.eof()&&kw_count<threshold)
            {
               fin>>tmp_kw;
               fin>>tmp_ind;
               kw_count++;
               if(kw_count %100 == 0)
            	   sse::logger::log(sse::logger::INFO) << "kw_count  "<<(kw_count)  << std::endl;
               s_req = client->search_request(tmp_kw);
               server.search(s_req);
             }
            end = clock();
            sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Report --------------" << std::endl;
            sse::logger::log(sse::logger::INFO) << std::dec<< "searching "<<(threshold) <<" <keyword in rocksdb " <<(end-start)<<" ms"<< std::endl;
            report<<"search\t"<<(threshold)<<"\t"<<(end-start)<<"\tdatabase\t"<<14*rnd_entries_count<<"\n";
            report.close();
            fin.close();

        }else{
        	 throw std::runtime_error("search bench are failed, please run update benchmark to setup database");
        }*/
    }else if(bench_code == 't'){
    	char *buffer;
		string parPath;
		if((buffer = getcwd(NULL, 0)) == NULL)
		{
			perror("getcwd error");
		}
		else
		{
			parPath = string(buffer) + "/cmp_bench/dataset/"+std::to_string(rnd_entries_count);
			input_file = parPath +"/pair"+std::to_string(bench_num)+".data\n";
		}
		string clientPath = parPath + "/pair"+std::to_string(bench_num);
		clientPath = clientPath + "/";

		client_master_key_path = clientPath+"uk.key";
		client_kw_indices_path = clientPath+"indices.dat";

		string reportPath = string(buffer) + "/report.csv";
		std::ofstream report;
		report.open(reportPath,std::ios_base::app);

		std::ifstream client_master_key_in(client_master_key_path.c_str());

		if(client_master_key_in.good() != true)
		{
			client_master_key_in.close();

			throw std::runtime_error("All streams are not in the same state");
		}

		if (client_master_key_in.good() == true) {
			std::stringstream client_master_key_buf;
			std::cout << "Restart client's master key and keyword indices file" << std::endl;
			client_master_key_buf << client_master_key_in.rdbuf();
			client.reset(new SfpseClient_core(client_master_key_buf.str(),client_kw_indices_path));
			SfpseServer server(clientPath+"server.dat");

			ifstream fin(input_file);
			if(!fin.is_open()){
				perror("data files can not open");
			}
			string tmp_kw;
			size_t tmp_ind;
			int kw_count=0;
			sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Starting --------------" << std::endl;
			clock_t  start, end;
			size_t threshold = 14*rnd_entries_count*getrate(rnd_entries_count);
			//sse::logger::log(sse::logger::INFO) << "threshold  "<<(threshold)  << std::endl;
			start  = clock();
			//while (!fin.eof()&&kw_count<threshold)
			//{
			   fin>>tmp_kw;
			   fin>>tmp_ind;
			   kw_count++;
			   if(kw_count %100 == 0)
				   sse::logger::log(sse::logger::INFO) << "kw_count  "<<(kw_count)  << std::endl;
			   s_req = client->search_request(tmp_kw);
			   server.search(s_req);
			// }
			end = clock();
			sse::logger::log(sse::logger::INFO) << "-------------- Search benchmark Report --------------" << std::endl;
			sse::logger::log(sse::logger::INFO) << std::dec<< "searching "<<(threshold) <<" <keyword in rocksdb " <<(end-start)<<" ms"<< std::endl;
			report<<"search\t"<<(threshold)<<"\t"<<(end-start)<<"\tdatabase\t"<<14*rnd_entries_count<<"\n";
			report.close();
			fin.close();

		}else{
			 throw std::runtime_error("search bench are failed, please run update benchmark to setup database");
		}


       /* if(token_bench_code == 's'){
            if (client_sk_in.good() == true) {
                cout << "loading client and server storage" << std::endl;
                std::stringstream client_sk_buf, client_master_key_buf, server_pk_buf;

                client_sk_buf << client_sk_in.rdbuf();
                client_master_key_buf << client_master_key_in.rdbuf();
                server_pk_buf << server_pk_in.rdbuf();

                LargeStorageSophosClient* client_=new LargeStorageSophosClient("client.sav", "client.csv", client_sk_buf.str(), client_master_key_buf.str()) ;

                //client.reset(new  LargeStorageSophosClient("client.sav", "client.csv", client_sk_buf.str(), client_master_key_buf.str()));
                server.reset(new SophosServer("server.dat", server_pk_buf.str()));

                ifstream fin(keyword_file);
                string tmp_kw;
                int kw_count=0;
                sse::logger::log(sse::logger::INFO) << "-------------- Search token gerneration benchmark Starting --------------" << std::endl;
                clock_t  start, end;
                start  = clock();
                while (!fin.eof())
                {
                   fin>>tmp_kw;
                   kw_count++;

                   s_req = client_->gen_search_token(tmp_kw);
                   server->gen_search_token(s_req);
                 }
                end = clock();
                sse::logger::log(sse::logger::INFO) << "-------------- Search token gerneration benchmark Report --------------" << std::endl;
                sse::logger::log(sse::logger::INFO) << std::dec<< "generate" <<(14*rnd_entries_count)<< " <keyword index> pair's search token in existing rocksdb spending " <<(end-start)<<" ms"<< std::endl;
                fin.close();

            }else{
                 throw std::runtime_error("search bench are failed, please run update benchmark to setup database");
            }
        }
        if(token_bench_code == 'u'){
            ifstream fin(input_file);
            string tmp_kw;
            size_t tmp_ind;
            cout << "Create new client-server instances" << std::endl;
            LargeStorageSophosClient* client_=new LargeStorageSophosClient("client.sav", "client.csv", 1000);

            // write keys to files
            ofstream client_sk_out(client_sk_path.c_str());
            client_sk_out << client_->private_key();
            client_sk_out.close();

            ofstream client_master_key_out(client_master_key_path.c_str());
            client_master_key_out << client_->master_derivation_key();
            client_master_key_out.close();

            clock_t  start, end;
            sse::logger::log(sse::logger::INFO) << std::dec<< rnd_entries_count<<std::endl;
            sse::logger::log(sse::logger::INFO) << "--------------update token gerneration benchmark starting --------------" << std::endl;
            start  = clock();
            while (!fin.eof())
            {
              fin>>tmp_kw;
              fin>>tmp_ind;
              client_->gen_update_token(tmp_kw, tmp_ind);
            }
            end = clock();
            sse::logger::log(sse::logger::INFO) << "-------------- update token gerneration benchmark Report --------------" << std::endl;
            sse::logger::log(sse::logger::INFO) << std::dec<< "generate" <<(14*rnd_entries_count)<< " <keyword index> pair's update token in empty rocksdb spending " <<(end-start)<<" ms"<< std::endl;
            fin.close();
        }*/
    }



    sse::crypto::cleanup_crypto_lib();


    return 0;
}
