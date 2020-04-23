# Setting up your own network in UNIX

1. Run 
```
setup.sh
```
3. Open 3 terminal windows or tabs and run the following commands:
```shell
python3 BlockchainDB.py
```
```shell
python3 BlockchainDB_5001.py 
```
```shell
python3 BlockchainDB_5002.py
```
4. The population of the chain has been stored into the populate.sh script, which updates the main chain then connects the nodes
```
populate.sh 
```
5. To check whether you chain updates on the connection of a new node, start your third node up:
```
python3 BlockchainDB_5003.py
```
6. Then connect the third node and check whether it also has the 12 documents that your main chain should have:
```
curl -d '{"nodes":["http://127.0.0.1:5000"]}' --header "Content-Type: application/json" --request POST http://0.0.0.0:5003/connect_node
curl http://0.0.0.0:5003/get_chain
```

Now that your nodes are connected feel free to play around with your BlockchainDB
    
Note:
    If you want to run this in debug mode run the following command before starting up your nodes:
    export `FLASK_ENV=development`

