Blog
====

A blog built on Google App Engine using python

A wiki page Built on Google App Engine using Python The readme has not been tested, and assumes you have the appengine python sdk at ~/appengine-python, and you have it on your system path.

After checking out this project navigate to the root folder of the project using the terminal.

Do an "ls", you should see a folder name "app/"

While here create an virtual env for python.

virtualenv env Then activate the virtual env

source gcd/bin/activate Now install all the dependencies

pip install webapp2

Link the appengine sdk to the virtual env

ln -s ~/appengine-python/google env/lib/python2.7/site-packages/google

Now you can run the app using

dev_appserver.py app
