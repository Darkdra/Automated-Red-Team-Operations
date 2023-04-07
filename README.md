Run with python -m flask run

Requires installing aws cli and configuring the access and secret key.

How to run in Linux:

```
#Install aws cli
sudo apt install awscli

#configure the aws cli by adding aws secret and access key
aws configure

#download the project folder
https://github.com/Darkdra/Automated-Red-Team-Operations.git 

#install the requirements.txt
pip install -r requirements.txt

#run the application
python -m flask run

#navigate to the app
http://127.0.0.1:5000/

#to load previous results without running the program again
http://127.0.0.1:5000/load

# to save results for future reference
http://127.0.0.1:5000/save
```

