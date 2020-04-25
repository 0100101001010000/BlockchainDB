# Setting up your own BlockchainDB in UNIX

This area will help you setup and run your own blockchain and connect 4 nodes up together.

To start with, run the `setup.sh` script, this will copy the BlockchainDB source code and make all the ports differents.

You will need to open 3 different terminal screens and start the nodes up by running the following:
```
python3 BlockchainDB.py
```
```
python3 BlockchainDB_5001.py 
```
```
python3 BlockchainDB_5002.py
```
Your nodes will be up and running now, but they still need to populated and connected. You can do this by running the `populate.sh` script which will populate the nodes for you and then connect them. You can also do this via the command line. 
To add documents via the command line:
```
curl -d '{"database key":"12345678","documents":{"1": "test document","2": "test document 2"},"signature":"Open"}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/
```
To connect nodes:
```
curl -d '{"nodes":["http://127.0.0.1:5001","http://127.0.0.1:5002"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5000/connect_node
```
To get the documents stored on a node:
```
curl http://0.0.0.0:5000/get_chain
```
To check whether your chain updates on the connection of a new node, start your third node up:
```
python3 BlockchainDB_5003.py
```
Then connect the third node and check whether it also has the documents that your main chain has:
```
curl -d '{"nodes":["http://127.0.0.1:5000"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5003/connect_node
curl http://0.0.0.0:5003/get_chain
```

Now that your nodes are connected feel free to play around with your new BlockchainDB
    
Note:
    If you want to run this in debug mode run the following command before starting up your nodes:
```
export FLASK_ENV=development
```
