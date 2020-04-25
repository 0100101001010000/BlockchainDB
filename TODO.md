# Things left to do

## Code:
* Implement Merkel trees.
    * Once done, change the code to stop using and comparing the entire chain for validity and updates.
* Replace hashlib with pycryptodome once there is an explanation for the increased time.
* Implement better sorting algorithms in get_document, as the longer the chains get the longer it will take.
* Enable retrieval of nodes from a saved file

## Build:
* Add pytest to github actions
    * It seems to be freezing on the collection, raise with pytest team
    
## Other:
* Deploy to GCP and AWS, connect, and **document**
* Do the wiki to explain how to use the chain properly (see wiki.txt)
* Milestone document
