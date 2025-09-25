import os
import uuid
import time
import boto3
import logging
from botocore.exceptions import ClientError
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Header
from wechatpayv3.async_ import AsyncWeChatPay, WeChatPayType
from decimal import Decimal
from typing import Dict
import jwt
import requests

AWS_REGION = os.environ.get("AWS_REGION")
COGNITO_USERPOOL_ID = os.environ.get("COGNITO_USERPOOL_ID")
COGNITO_APP_CLIENT_ID = os.environ.get("COGNITO_APP_CLIENT_ID")
mchid = os.environ.get("WXPAY_MCHID")
private_key = os.environ.get("WXPAY_PRIVATE_KEY")
cert_serial_no = os.environ.get("WXPAY_CERT_SERIAL_NO")
apiv3_key = os.environ.get("WXPAY_APIV3_KEY")
appid = os.environ.get("WXPAY_APP_ID")
notify_url = os.environ.get("NOTIFY_URL")
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
TRANSACTIONS_TABLE = dynamodb.Table('vocable-transactions')
USERS_TABLE = dynamodb.Table('vocable-userinfo') 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if not all([os.environ.get('AWS_ACCESS_KEY_ID'), os.environ.get('AWS_SECRET_ACCESS_KEY')]):
    logging.warning("AWS credentials not found in environment variables")

JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"

jwks_cache = {
    "keys": [],
    "last_fetched": 0,
    "ttl": 3600 
}

def get_jwks() -> Dict:
    now = time.time()
    if now - jwks_cache["last_fetched"] > jwks_cache["ttl"]:
        try:
            response = requests.get(JWKS_URL)
            response.raise_for_status()
            jwks_cache["keys"] = response.json()["keys"]
            jwks_cache["last_fetched"] = now
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch JWKS: {e}")
            raise HTTPException(status_code=500, detail="Could not fetch authentication keys.")
    return jwks_cache["keys"]

async def get_current_user(authorization: str = Header(...)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.split(" ")[1]
    
    try:
        jwks = get_jwks()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Could not find appropriate key")
        
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key)

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=COGNITO_APP_CLIENT_ID,
            issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
        )

        user_id = payload.get("sub")
        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError as e:
        logging.error(f"JWT Verification Error: {e}")
        raise HTTPException(status_code=401, detail="Could not validate token")
    except Exception as e:
        logging.error(f"An unexpected error occurred during auth: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

wxpay = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global wxpay
    wxpay = AsyncWeChatPay(
        wechatpay_type=WeChatPayType.APP,
        mchid=mchid,
        private_key=private_key,
        cert_serial_no=cert_serial_no,
        apiv3_key=apiv3_key,
        appid=appid,
        notify_url=notify_url,
        cert_dir='/tmp/cert'
    )
    await wxpay.__aenter__()
    yield
    if wxpay:
        await wxpay.__aexit__(None, None, None)

app = FastAPI(lifespan=lifespan)

@app.post("/pay")
async def create_payment(user_id: str = Depends(get_current_user)):
    out_trade_no = str(uuid.uuid4()).replace('-', '')
    total = 5000
    description = "Vocable One-Time Test"

    try:
        TRANSACTIONS_TABLE.put_item(
            Item={
                'out_trade_no': out_trade_no,
                'user_id': user_id,
                'description': description,
                'status': 'PENDING',
                'amount': total,
                'created_at': int(time.time())
            }
        )
    except ClientError as e:
        logging.error(f"DynamoDB Error creating pending transaction: {e}")
        raise HTTPException(status_code=500, detail="Error initiating transaction.")
    
    code, message = await wxpay.pay(
        description=description,
        out_trade_no=out_trade_no,
        amount={'total': total},
        pay_type=WeChatPayType.APP
    )

    if code == 200:
        logging.info(f"Preparing to send params to frontend: {message}")
        return {"params": message, "out_trade_no": out_trade_no}
    else:
        logging.error(f"WeChat Pay API failed with code {code}: {message}")
        raise HTTPException(status_code=code, detail=message)

@app.post("/notify")
async def handle_notification(request: Request):
    headers = dict(request.headers)
    body = await request.body()
    result = await wxpay.callback(headers, body.decode('utf-8'))

    if not (result and result.get('event_type') == 'TRANSACTION.SUCCESS'):
        logging.error(f"Notification failed validation or was not a success event: {result}")
        return Response(content='{"code": "400", "message": "FAILURE"}', media_type="application/json")

    resource = result.get('resource', {})
    out_trade_no = resource.get('out_trade_no')
    trade_state = resource.get('trade_state')

    if trade_state != 'SUCCESS':
        return Response(content='{"code": "200", "message": "SUCCESS"}', media_type="application/json")

    try:
        response = TRANSACTIONS_TABLE.get_item(Key={'out_trade_no': out_trade_no})
        item = response.get('Item')
        if not item:
            logging.error(f"Received notification for unknown transaction: {out_trade_no}")
            return Response(content='{"code": "400", "message": "FAILURE"}', media_type="application/json")
        
        user_id = item.get('user_id')

        TRANSACTIONS_TABLE.update_item(
            Key={'out_trade_no': out_trade_no},
            UpdateExpression="SET #s = :completed",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':completed': 'COMPLETED', ':pending': 'PENDING'}
        )

        USERS_TABLE.update_item(
            Key={'UUID': user_id},
            UpdateExpression="ADD #c :val",
            ExpressionAttributeNames={'#c': "Count"},
            ExpressionAttributeValues={':val': Decimal(1)}
        )

        logging.info(f"Successfully processed transaction: {out_trade_no} for user: {user_id}")

    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logging.info(f"Received duplicate notification for already processed transaction: {out_trade_no}")
        else:
            logging.error(f"DynamoDB Error processing notification: {e}")
            return Response(content='{"code": "500", "message": "FAILURE"}', media_type="application/json")
    
    return Response(content='{"code": "200", "message": "SUCCESS"}', media_type="application/json")

@app.get("/query/{out_trade_no}")
async def query_payment(out_trade_no: str):
    try:
        response = TRANSACTIONS_TABLE.get_item(Key={'out_trade_no': out_trade_no})
        item = response.get('Item')

        if item:
            return {"source": "database", "status": item.get('status'), "data": item}

        code, message = await wxpay.query(out_trade_no=out_trade_no)
        return {"source": "wechat_api", "code": code, "message": message}

    except ClientError as e:
        logging.error(f"DynamoDB Error in /query: {e}")
        raise HTTPException(status_code=500, detail="Error querying transaction.")




