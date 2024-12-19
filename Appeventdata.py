from flask import Flask, jsonify, request
from elasticapm.handlers.logging import LoggingHandler
from flask_cors import CORS
import os,logging,traceback,time
from elasticapm.contrib.flask import ElasticAPM
from authlib.jose import jwt
from functools import wraps
from datetime import datetime
from elasticsearch_dsl import connections
from dotenv import load_dotenv
load_dotenv()
public_key = os.getenv('PUBLIC_KEY')
Service_Name = os.getenv('SERVICE_NAME')
Server_Url = os.getenv('SERVER_URL')
Secret_token = os.getenv('SECRET_TOKEN')
Environment = os.getenv('ENVIRONMENT')
log_level = os.getenv('LOG_LEVEL')
import time

ELK_USERNAME = os.getenv('ELK_USERNAME')
ELK_PASSWORD = os.getenv('ELK_PASSWORD')
Elk_Endpoint = os.getenv('ELK_ENDPOINT')
ELK_INDEX = os.getenv('ELK_INDEX')
es=connections.create_connection(hosts=[Elk_Endpoint],timeout=1200,http_auth=(ELK_USERNAME,ELK_PASSWORD))

Errormsg = "No records found"
app = Flask(__name__)
CORS(app)
key = '-----BEGIN PUBLIC KEY-----\n' + public_key + '\n-----END PUBLIC KEY-----'
key_binary = key.encode('ascii')

cors = CORS(app, resources={ 
    r"/*": { 
        "Access_Control_Allow_Origin": "*",
        "origins": "*",
        "allowedHeaders" :'Content-Type, Authorization, Origin, X-Requested-With, Accept',
        "method":['GET','POST','PATCH','DELETE','PUT']
           }
})

app.config['ELASTIC_APM'] = {
    'SERVICE_NAME':Service_Name,
    'SERVER_URL': Server_Url,
    'SECRET_TOKEN': Secret_token,
    'ENVIRONMENT' : Environment,
    'LOG_LEVEL' : log_level 
}

apm = ElasticAPM(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({"message": "Token is missing "}), 401

        try:
            claims = jwt.decode(token, key_binary)
            claims.validate()
            if (claims is not None ) and (time.time() < claims['exp']):
                print("Token Verified!!! ")

            else:
                print("Token is expired!!")

        except Exception as e:
            print(e)
            print(traceback.format_exc())
            return jsonify({'msg':'some token error!!!'}), 401
        return f(*args, **kwargs)
    return decorated

# Custom middleware to Protection header to all responses
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy']='default-src \'self\''
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return resp


def injectappeventdatainto_elk(Appevent_details,indexname):  
    now = datetime.now()
    currentdate = now.strftime('%Y-%m-%d %H:%M:%S') 

    for Appevent in Appevent_details:
        Appevent.update( {'elk_created_dt' : currentdate} )
        res=es.index(index=indexname, ignore=400, document = Appevent)
        print(res)
        result_msg = "Success"

    return result_msg

# Registration    
@app.route('/registrationevent', methods=['POST'])
# @token_required

def registrationevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_register_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg })

# Basic Preferences setting after registering    
@app.route('/basicpreferenceevent', methods=['POST'])
@token_required

def basicpreferenceevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_basicpreference_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg })      
  
  # Searches and Job applies    
@app.route('/searchevent', methods=['POST'])
@token_required

def searchevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_search_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg })    
       
# Resume  
@app.route('/createresumeevent', methods=['POST'])
@token_required

def createresumeevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_createresume_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg })  
       
# Retention  
@app.route('/retentionevent', methods=['POST'])
@token_required

def retentionevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_retention_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg })  
       
# Basic user traction  
@app.route('/basictractionevent', methods=['POST'])
@token_required

def basictractionevent():

    try:

        Appevent_details =request.json['Appevent_Details']    

        result_msg=injectappeventdatainto_elk(Appevent_details,"user_basictraction_idx")          

        return jsonify({'msg':result_msg })     

    except Exception:

           return jsonify({'msg':Errormsg }) 
           
'''API Call'''
if __name__ == '__main__':
    handler = LoggingHandler(client=apm.client)
    handler.setLevel(logging.WARN)
    app.logger.addHandler(handler)
    app.run(host='0.0.0.0', port=5000)
    # app.run()      
