#!/bin/bash

# remove any old code files
rm -r BlockchainDB*.py

# copy over latest copy of the code
cp ../BlockchainDB.py .
cp BlockchainDB.py BlockchainDB_5001.py
cp BlockchainDB.py BlockchainDB_5002.py
cp BlockchainDB.py BlockchainDB_5003.py

#change last two lines of different nodes
sed -i 's/port = 5000/port = 5001/g' BlockchainDB_5001.py
sed -i 's/port = 5000/port = 5002/g' BlockchainDB_5002.py
sed -i 's/port = 5000/port = 5003/g' BlockchainDB_5003.py
