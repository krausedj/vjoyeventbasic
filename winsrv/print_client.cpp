/*
 * Copyright (c) 2016, Peter Thorson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#define ASIO_STANDALONE
#include "boost_config.hpp"
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <json/json.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
void sha256(const char * input, unsigned char * output)
{
    memset(output, 0 , SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(output, &sha256);
}

/* A BASE-64 ENCODER AND DECODER USING OPENSSL */

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = static_cast<char *>(calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) )); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

typedef websocketpp::client<websocketpp::config::asio_client> client;
client c;

//https://github.com/obsproject/obs-websocket/blob/7893ae5caafecddb9589fe90719809b4f528f03e/docs/docs/partials/introduction.md
void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg) {
	std::cout << msg->get_payload() << std::endl;

    Json::Value root;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse( msg->get_payload(), root );
    //The obs op code is different then the websocket op code
    //  Websocket is like, TEXT or BINARY
    //    Which OBS treats as JSON or MsgPack (IDK the later)
    //  ObsOpCode is like, Hello (uncle leo), Identify, etc
    int obs_op_code{root["op"].asInt()};
    if (0 == obs_op_code){
        //Hello op code
        std::string password{"YuibGljTGcSpi450"};
        std::string salt{root["d"]["authentication"]["salt"].asString()};
        std::string challenge{root["d"]["authentication"]["challenge"].asString()};
        std::string pass_salt = password + salt;
        unsigned char secret_sha[SHA256_DIGEST_LENGTH];
        sha256(pass_salt.c_str(), secret_sha);
        std::string secret_b64{base64encode(secret_sha, SHA256_DIGEST_LENGTH)};
        std::string auth_str = secret_b64 + challenge;
        unsigned char auth_sha[SHA256_DIGEST_LENGTH];
        sha256(auth_str.c_str(), auth_sha);
        std::string auth_b64{base64encode(auth_sha, SHA256_DIGEST_LENGTH)};
        
        std::cout << password << std::endl;
        std::cout << salt << std::endl;
        std::cout << challenge << std::endl;
        std::cout << pass_salt << std::endl;
        std::cout << secret_b64 << std::endl;
        std::cout << auth_str << std::endl;
        std::cout << auth_sha << std::endl;
        std::cout << auth_b64 << std::endl;
        
        Json::Value response;
        response["op"] = 1;

        response["d"]["rpcVersion"] = 1;
        response["d"]["authentication"] = auth_b64;

        Json::FastWriter fastWriter;
        std::string response_string = fastWriter.write(response);

        std::cout << response_string << std::endl;
        c.send(hdl, response_string, websocketpp::frame::opcode::text);
    }
}

int main(int argc, char* argv[]) {

    std::string uri = "ws://localhost:4455";

    if (argc == 2) {
        uri = argv[1];
    }

	try {
        // Set logging to be pretty verbose (everything except message payloads)
        c.set_access_channels(websocketpp::log::alevel::all);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);
        c.set_error_channels(websocketpp::log::elevel::all);

        // Initialize ASIO
        c.init_asio();

        // Register our message handler
        c.set_message_handler(&on_message);

        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);
        if (ec) {
            std::cout << "could not create connection because: " << ec.message() << std::endl;
            return 0;
        }

        // Note that connect here only requests a connection. No network messages are
        // exchanged until the event loop starts running in the next line.
        c.connect(con);

        // Start the ASIO io_service run loop
        // this will cause a single connection to be made to the server. c.run()
        // will exit when this connection is closed.
        c.run();
    } catch (websocketpp::exception const & e) {
        std::cout << e.what() << std::endl;
    }
}
