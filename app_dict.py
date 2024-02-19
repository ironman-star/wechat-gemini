# encoding=utf-8
import json
import logging
import re
import struct
import time
from base64 import b64decode
from datetime import datetime
from hashlib import sha1
from threading import Thread
from urllib.parse import unquote
import google.generativeai as genai
import redis
import requests
import xmltodict
from Crypto.Cipher import AES
from flask import Flask, request, Response
import markdown
from bs4 import BeautifulSoup
user2session = {}

logging.basicConfig(format='%(asctime)s %(filename)s %(lineno)s %(levelname)s - %(message)s',
                    filename="debug.log", level=logging.DEBUG)
pool = redis.ConnectionPool(host='localhost', port=6379, db=3, decode_responses=None)
redis_client = redis.Redis(connection_pool=pool)
token_file = 'token.json'
with open('conf.json') as f:
    dic = json.load(f)
generation_config = dic['generation_config']
safety_settings = dic['safety_settings']
relation = dic['relation']
corp_id = dic['corp_id']
gemini_api_key = dic['genimi']['api_key']
genai.configure(api_key=gemini_api_key)
model = genai.GenerativeModel('gemini-pro', generation_config=generation_config,
                              safety_settings=safety_settings)

app = Flask(__name__)


def get_token(agent_id):
    secret = relation[agent_id]['secret']
    token = redis_client.get("token_" + agent_id)
    if token is None:
        logging.info("token expire, try to refresh it!")
        refresh_token(secret, agent_id)
        return get_token(agent_id)
    return token.decode('utf-8')


def refresh_token(secret, agent_id):
    params = {
        'corpid': corp_id,
        'corpsecret': secret
    }
    try:
        logging.info("try get token")
        res = requests.get('https://qyapi.weixin.qq.com/cgi-bin/gettoken', params=params, verify=True).json()
        logging.info("response is %s" % res)
    except Exception as e:
        time.sleep(3)
        refresh_token(secret, agent_id)
    else:
        redis_client.set("token_" + agent_id, res['access_token'], ex=7000)


def cut(s):
    tmp_list = []
    all_con = s.split("\n")
    flag = False
    for i in range(0, len(all_con)):
        if len("\n".join(all_con[0:i + 1]).encode()) > 2040:
            flag = True
            first = "\n".join(all_con[0:i])
            tmp_list.append(first)
            last = "\n".join(all_con[i:])
            tmp_list += cut(last)
            break
    if flag is False:
        return [s]
    else:
        return tmp_list


def send(agent_id, user, s_message, last=False, message_type="text"):
    access_token = get_token(agent_id)
    logging.info("start post")
    l = cut(s_message)
    if last:
        l = [l[-1]]
    logging.info(l)
    for i in range(0, len(l)):
        if l[i] == "":
            continue
        params = {
            "touser": user,
            "msgtype": message_type,
            "agentid": int(agent_id),
            "text": {"content": l[i]},
            "markdown": {"content": l[i]},
            "safe": 0,
            "enable_id_trans": 0,
            "enable_duplicate_check": 0,
            "duplicate_check_interval": 1800
        }
        try:
            response = requests.post('https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s' % access_token,
                                     json=params, verify=True).json()
            time.sleep(0.5)
        except Exception as e:
            time.sleep(5)
            send(agent_id, user, s_message)


def response_for_request(request, agent_id):
    decrypto_token = relation[agent_id]["decrypto_token"]
    EncodingAESKey = relation[agent_id]["EncodingAESKey"]
    AESKey = b64decode(EncodingAESKey + "=")
    ciper = AES.new(AESKey, 2, AESKey[0:16])
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")
    if request.method == "POST":
        # try:
        data = request.get_data(as_text=True)
        encrypt_xml = xmltodict.parse(data)['xml']
        encrypt = encrypt_xml.get("Encrypt")
        signature = sha1("".join(sorted([decrypto_token, timestamp, nonce, encrypt])).encode("utf-8")).hexdigest()
        if msg_signature == signature:
            content = ciper.decrypt(b64decode(encrypt))[16:]
            pad = ord(chr(content[-1]))
            content = content[:-pad]
            msg_len = content[0:4]
            testResult = sum(struct.unpack('>HH', msg_len))
            msg = content[4:testResult + 4]
            in_dic = xmltodict.parse(msg)['xml']
            xml_content = in_dic.get('Content')
            user = in_dic.get('FromUserName')
            logging.info(json.dumps(in_dic))
            xml_event_key = in_dic.get('EventKey')
            msg_id = in_dic.get("MsgId")
            if msg_id and redis_client.hexists("message", msg_id):
                logging.warning("get exists msg id %s" % msg_id)
                return Response(status=200, response="")
            elif msg_id:
                redis_client.hset("message", msg_id, json.dumps(in_dic))
            if xml_content is not None:
                message = xml_content
            elif xml_event_key is not None:
                message = xml_event_key
            else:
                logging.error("call failed")
                send(agent_id, user, "调用失败！")
                return Response(status=200, response="")
            if agent_id == "1000009":
                chat(agent_id, user, message)
            else:
                pass
        # except Exception as e:
        #     logging.error("something is wrong, error is %s" % e)
        return Response(status=200, response="")
    elif request.method == "GET":
        try:
            echostr = unquote(request.args.get("echostr"))
            signature = sha1("".join(sorted([decrypto_token, timestamp, nonce, echostr])).encode("utf-8")).hexdigest()
            aes_meg = b64decode(echostr)
            content = ciper.decrypt(aes_meg)[16:]
            pad = ord(chr(content[-1]))
            content = content[:-pad]
            msg_len = content[0:4]
            testResult = sum(struct.unpack('>HH', msg_len))
            msg = content[4:testResult + 4]
            receiveid = content[testResult + 4:]
            if msg_signature == signature:
                return msg
            return "hello world!"
        except Exception as e:
            print(e)
            return "hello world!"


def convert_to_text(input_str):
    html = markdown.markdown(input_str)
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text(separator=' ')
    if text.startswith('\n'):
        text = text[1:]
    return text


def chat(agent_id, user, message):
    logging.debug("%s ask gemini: %s" % (user, message))
    send(agent_id, user, "")
    if message == "#开始":
        chat_session = model.start_chat(history=[])
        user2session[user] = chat_session
        send(agent_id, user, "对话模式开始。。。")
    elif message == "#结束":
        if user in user2session:
            del(user2session[user])
        send(agent_id, user, "对话模式结束。。。")
    else:
        if user not in user2session:
            res = model.generate_content(message).text
        else:
            logging.info("history is " + str(user2session[user].history))
            chat_session = user2session[user]
            res = chat_session.send_message(message).text
            user2session[user] = chat_session
        response = convert_to_text(res)
        logging.info("Gemini answer is %s " % res)
        send(agent_id, user, response)


@app.route("/gemini_chat", methods=["POST", "GET"])
def gemini_chat():
    return response_for_request(request, "1000009")


@app.route("/", methods=["GET"])
def hello():
    return "Hello there!"


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8081, debug=True)
