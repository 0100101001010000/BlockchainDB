# BlockchainDB
A simple NoSQL database blockchain built using [Flask](https://flask.palletsprojects.com/en/1.1.x/).

BlockchainDB uses the blockchain techonology to provide a safe and decentralised database, meaning that your data is safer as it is copied a.cross multiple nodes limiting the ability of someone to corrupt your data. This also means that each node is a failover for the other, if one fails the others will have the same data so will still be able to run your query. BlockchainDB also allows you to upload encrypted data so that only people with the keys can decrypt it.

## Installation
Fork this repository and make it you own.

## Testing
BlockchainDB uses [Pytest](https://docs.pytest.org/en/latest/), the test cases can be found in `test_BlockchainDB.py` which can run from the command line:
```shell
pytest -v
```

## Usage
The intention of this repository is to be forked and adapted to different projects.  

## Examples
The Example directory has an example that allows you to start up your own chain and connect a couple of nodes together, more details can be found in the directory [README.md](https://github.com/0100101001010000/BlockchainDB/blob/master/Example/README.md)
### Queries
#### Connecting a node
/connect_node

method: POST

data: {"nodes":["http://host:node","http://host:node",...]}

#### Getting all the documents from a chain
/get_chain

method: GET

#### Getting the latest version of a document
/get_latest

method: POST

data: {'database key': database_key, 'document key': document_key}

#### Getting a specific version of a document
get_version

method: POST

data: {'database key': database_key, 'document key': doc1_key, 'version': 0}

#### Getting all versions of a specific document
/get_all_versions

method: POST

data: {'database key': database_key, 'document key': document_key}

#### Getting all documents in a database
/get_all_db_documents

method: POST

data: {'database key': database_key}

#### Creating a document
/create_document

method: POST

data: {'database key': database_key, 'document': 'test document', 'signature': 'Open'}

The 'signature' at the end determines whether or not your document can be updated without using an encrypted signature, if you want your document to be manipulated by everyone use 'Open'. This will be covered in more detail in the Encryption section.

#### Creating multiple documents
/create_document

method: POST

data: {'database key': database_key, 'documents': {'document1': 'test document 1', 'document2': 'test document 2',...}, signature': 'Open'}

The 'signature' at the end determines whether or not your documents can be updated without using an encrypted signature, if you want your document to be manipulated by everyone use 'Open'. This will be covered in more detail in the Encryption section.

#### Updating a document
/update_document

method: POST

data: {'database key': database_key, 'document key': doc_key, 'document': 'test document update', 'signature': 'Open'}

/update_document can also be used to change the access to a document, if you change the 'signature' from 'Open' to a signature or vice versa this will change the level of access to your document.

## Deployment
BlockchainDB uses Flask for more information see their [deployment page](https://flask.palletsprojects.com/en/1.1.x/deploying/#deployment).

## Contributing
Raise an issue to discuss the improvement or bug fix, then a pull request can be raised. More information can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/CONTRIBUTING.md) 

## Code of conduct
The code of conduct can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/CODE_OF_CONDUCT.md)

## License
BlockchainDB falls under the MIT license, more information can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/LICENSE.md)
