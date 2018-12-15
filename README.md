# Catalog_App
A Python web application that allows a logged in user to create a catalog of categories and items.
## Requirements
- Python 2
- sqlalchemy
- A Vagrant environment.
  - Included in this repo: vagrant_config.zip (includes python and sqlalchemy)

## Preparing the environment
  1. Download Vagrant from here: https://www.vagrantup.com/downloads.html
  2. Unzip the Vagrant_Config.zip into a directory.
    - Vagrant_Config.zip is available in this repo.
  3. Navigate to the newly created unzipped directory (ie c:/vagrant_config).
  4. Start the Vagrant environment (vagrant up).
  5. Login to Vagrant (vagrant ssh).
  6. Congratulations, your environment is set up, proceed to running the program!

## Running the Program
- Ensure all the requirements are met.
- Navigate to the directory web_server.py is located in.
- From the console type the following:
    - `python web_server.py`

## Attributions
- The vagrant_config.zip file is from Udacity's Full Stack Web Development Nanodegree.
