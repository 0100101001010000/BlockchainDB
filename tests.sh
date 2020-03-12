#!/bin/bash

# get chain
curl http://0.0.0.0:5000/get_chain

# create a document
curl -d '{"database key":"12345678","document":"test document","encrypt":"True"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_document
curl http://0.0.0.0:5000/get_chain

# create multiple documents
curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"encrypt":"True"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl http://0.0.0.0:5000/get_chain

# get latest
curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"encrypt":"True"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_documents
curl -d '{"database key": "12345678","document key":"6a33352d-8e2d-47cf-8107-bc55126672c3"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/get_latest
curl http://0.0.0.0:5000/get_chain

