## Project: Item Catalog

A web application that allows access, modification and addition of recipes to food categories. The application implements user registration and third party OAuth authentication. Specifically all content is available to all site users but recipe item updates/deletions can only be performed by the item creator. Items can also only be added if a user is logged in via Google or Facebook.

**Installation Requirements**
Using a virtual machine (VM) is recommended to isolate dependency configurations in a disposable environment. [Vagrant](https://www.vagrantup.com/downloads.html) and [Virtual Box](https://www.virtualbox.org/wiki/Downloads) can be installed to manage the VM. The VM configuration can be cloned from [Github](https://github.com/udacity/fullstack-nanodegree-vm). To start the virtual machine, from the terminal change to the directory containing the files cloned from github, then change to a directory called vagrant found inside that directory. Run the command `vagrant up` and then the command `vagrant ssh`.

Within the vagrant directory also save the web application files. The program source code can be run in Python 2 versions that can be downloaded from the [Python downloads page](https://www.python.org/downloads/). The application uses a [flask](http://flask.pocoo.org/docs/0.12/installation/) framework and connects to a database via [SQLAlchemy](http://docs.sqlalchemy.org/en/latest/intro.html) to access the food categories and saved recipes.

For the application to implement third party authorization you have to create a client ID and client secret with [Google](https://support.google.com/googleapi/answer/6158862?hl=en) and [Facebook](https://developers.facebook.com/docs/pages/getting-started). You can set the site URL of the web application to be "http://localhost:8000". Accessing the credentials menu in the google developer's page, select the option to download JSON and save that file in the same directory as the application under the name "client_secrets" replacing the existing file under that name. Alternatively, open the existing client_secrets.json and add your Google client ID and secret were prompted. Then open the fb_client_secrets.json file and add your Facebook client ID and secret where prompted. Also, open the login.html in a text editor and add your Google and Facebook client IDs were prompted. 

**Usage**
To run the program start up the VM and run the command `python data.py`. This should output a "items added!" message and a new file "categoriesappwithusers.db" should also appear in the application directory. Then run `python project.py` and try visiting the site's URL from your browser.  

**Credits**
Developer - DemetraSkl
The project topic and specifications have been created by Udacity.
User registration and authentication mathods have been based on [code](https://github.com/udacity/ud330) developed by Udacity.


**License**

MIT License

Copyright (c) [2017] [DemetraSkl]