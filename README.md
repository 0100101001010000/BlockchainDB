# BlockchainDB
A simple NoSQL database blockchain built using [Flask](https://flask.palletsprojects.com/en/1.1.x/).

BlockchainDB uses the blockchain techonology to provide a safe and decentralised database, meaning that your data is safer as it is copied a.cross multiple nodes limiting the ability of someone to corrupt your data. This also means that each node is a failover for the other, if one fails the others will have the same data so will still be able to run your query. BlockchainDB also allows you to upload encrypted data so that only people with the keys can decrypt it.

## Installation
Fork this repository and make it you own.

## Testing
BlockchainDB uses [Pytest](https://docs.pytest.org/en/latest/), the test cases can be found in `test_BlockchainDB.py` which can run from the command line, just type `pytest -v` and the tests should run.

## Usage
The intention of this repository is to be forked and adapted to different projects.  

## Examples
The Example directory has an example that allows you to start up your own chain and connect a couple of nodes together, more details can be found in the directory [README.md](https://github.com/0100101001010000/BlockchainDB/blob/master/Example/README.md)

## Deployment
BlockchainDB uses Flask for more information see their [deployment page](https://flask.palletsprojects.com/en/1.1.x/deploying/#deployment).

## Contributing
Raise an issue to discuss the improvement or bug fix, then a pull request can be raised. More information can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/CONTRIBUTING.md) 

## Code of conduct
The code of conduct can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/CODE_OF_CONDUCT.md)

## License
BlockchainDB falls under the MIT license, more information can be found [here](https://github.com/0100101001010000/BlockchainDB/blob/master/LICENSE.md)
