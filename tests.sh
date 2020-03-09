#!/bin/bash

# get chain
curl http://0.0.0.0:5000/get_chain

# create a document
curl -d '{"database_key":"12345678","document":"test document","encrypt":"True"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/create_document
curl http://0.0.0.0:5000/get_chain

# create multiple documents

