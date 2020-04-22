#!/bin/bash

# remove any old code files
rm -r BlockchainDB*.py

# copy over latest copy of the code
cp ../BlockchainDB.py .
cp BlockchainDB.py BlockchainDB_5001.py
cp BlockchainDB.py BlockchainDB_5002.py
cp BlockchainDB.py BlockchainDB_5003.py

#change last two lines of different nodes

# run different nodes
#python3 BlockchainDB.py
#python3 BlockchainDB_5001.py &
#python3 BlockchainDB_5002.py &
#python3 BlockchainDB_5003.py &

