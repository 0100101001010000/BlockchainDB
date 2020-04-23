#!/bin/bash

# This should prove that the connectivity between nodes works properly
# Start up each node by running the python script:
# For node 5000:
# $python3 BlockchainDB.py
# For other nodes:
# $python3 BlockchainDB_500x.py
# I would recommend starting up 5000, 5001, and 5002 first then 5003 later to check whether it updates properly

# Populate node at port 5000
curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 3","2": "test document 4"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 5","2": "test document 6"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 7","2": "test document 8"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key":"12345678","documents":{"1": "test document 9","2": "test document 10"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents

# Populate node at port 5001
curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents

# Connect 5000 to 5001 and 5002
curl -d '{"nodes":["http://127.0.0.1:5001","http://127.0.0.1:5002"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/connect_node

# Update 5000 to see whether it feeds
curl -d '{"database key":"12345678","document":"test post node connection","signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_document

# Node 5000 should have 12 documents
curl http://0.0.0.0:5000/get_chain

# Node 5001 should also have 12 documents and the document it created on line 13 should have been replaced
curl http://0.0.0.0:5001/get_chain

# Node 5002 should have 12 documents
curl http://0.0.0.0:5002/get_chain

# To check whether starting up a new node and then connecting it gets the correct data run the follwing once this has run
# python3 BlockchainDB_5003.py
# curl -d '{"nodes":["http://127.0.0.1:5000"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5003/connect_node
# Your four nodes should be fully connected, have fun.
