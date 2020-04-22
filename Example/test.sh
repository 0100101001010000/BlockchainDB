#!/bin/bash

curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 3","2": "test document 4"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 5","2": "test document 6"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 7","2": "test document 8"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 9","2": "test document 10"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents

curl http://0.0.0.0:5000/get_chain

#curl -d '{"nodes":["http://127.0.0.1:5001","http://127.0.0.1:5002","http://127.0.0.1:5003"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/connect_node
curl -d '{"nodes":["http://127.0.0.1:5001"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/connect_node
#curl -d '{"nodes":["http://127.0.0.1:5000"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5001/connect_node

curl -d '{"database key":"12345678","document":"test post node connection","signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_document

curl http://0.0.0.0:5000/get_chain
curl http://0.0.0.0:5001/get_chain

#connect nodes and run pytest for above
