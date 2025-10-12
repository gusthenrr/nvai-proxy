from flask import Flask, request, jsonify, redirect, session, make_response,Response, stream_with_context
from flask_cors import CORS, cross_origin
import requests
import eventlet
eventlet.monkey_patch()
from psycogreen.eventlet import patch_psycopg
patch_psycopg()
import uuid
from uuid import UUID
import hashlib
import base64
import os,time, threading, json
import re, unicodedata, requests
import random
from collections import defaultdict
from langchain_core.runnables import RunnableLambda
import threading
from flask_socketio import SocketIO,emit, join_room
from flask_session import Session
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from datetime import datetime,timedelta, date, time, timezone
from flask_jwt_extended import JWTManager, create_access_token,jwt_required,get_jwt_identity,decode_token
from openai import OpenAI
from dotenv import load_dotenv
import json
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from jwt import ExpiredSignatureError, InvalidTokenError
import time
from langchain.callbacks.tracers import LangChainTracer 
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate , MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
from langchain_core.output_parsers import StrOutputParser
from pydantic import BaseModel, Field
from langchain.prompts.few_shot import FewShotPromptTemplate
from langchain.prompts.prompt import PromptTemplate
from typing import Optional, List, Any, Dict, Literal,Tuple

DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = 'novai'
DB_USER = 'postgres'
DB_PASSWORD = 'S3t3mbro41'
def get_db_connection():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL não definido")
    return psycopg2.connect(url, cursor_factory=RealDictCursor)

app = Flask(__name__)
ALLOWED_ORIGIN = "https://app.nossopoint-backend-flask-server.com"
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGIN, async_mode='eventlet', ping_interval=20, ping_timeout=120)
load_dotenv(".env.local")
app.secret_key = os.getenv("FLASK_SECRET_KEY") 
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Impede que scripts acessem os cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Se True, só permite cookies via HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = "None"
#Config do jwt
app.config["JWT_SECRET_KEY"] = "aquiumachavebemsegura"
jwt = JWTManager(app)
from http.cookiejar import MozillaCookieJar

Session(app)  # Inicializa a sessão
CORS(app, supports_credentials=True, resources={r"/*": {"origins": [ALLOWED_ORIGIN]}})

url_global="https://nossopoint-backend-flask-server.com"
# 🔑 Suas credenciais do Mercado Livre
CLIENT_ID = "3414621845496970"
CLIENT_SECRET = "Zn1vIKKBbucQvaR9BRxcg6ufGn39iW4h"
# 🌎 URL de redirecionamento configurada no painel do Mercado Livre
REDIRECT_URI = f"{url_global}/callback"


api_key = os.getenv("OPENAI_API_KEY")
LangChainTracer(project_name="novo_projeto")
client = OpenAI(api_key=api_key)

COOKIE_NAME = "__Host-token"

def set_auth_cookie(resp, jwt_value: str):
    resp.set_cookie(
        key=COOKIE_NAME,
        value=jwt_value,
        httponly=True,
        secure=True,
        samesite="None",
        path="/",          # obrigatório para __Host-
        # sem Domain -> host-only
        max_age=60*60*24,
    )
    return resp

def clear_legacy_cookies(resp):
    # apaga qualquer 'token' residual (host-only)
    resp.set_cookie("token", "", max_age=0, path="/", secure=True, samesite="None")
    # apaga variações com Domain que podem ter ficado
    for d in [".nossopoint-backend-flask-server.com", "app.nossopoint-backend-flask-server.com"]:
        resp.set_cookie("token", "", max_age=0, path="/", domain=d, secure=True, samesite="None")
    return resp


# CRIAR CONTA DE USUARIO DA NOVAI
@app.route('/add-usuario', methods=['POST'])
def add_usuario():
    print('Entrou no add-usuario')
    try:
        email = request.form.get('email')
        senha = request.form.get('senha')
        usuario = request.form.get('usuario')  # Novo campo

        if not email or not senha or not usuario:
            return jsonify({"error": "Usuário, email e senha são obrigatórios"}), 400

        # Gerando o hash da senha com bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(senha.encode('utf-8'), salt).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()

        # Verificar se o email já está cadastrado
        cur.execute("SELECT * FROM usuarios WHERE email = %s;", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Usuário já cadastrado"}), 400

        #Inserir novo usuário no banco de dados
        cur.execute(
            "INSERT INTO usuarios (usuario, email, senha,modo_automatico) VALUES (%s, %s, %s,%s) RETURNING id;",
            (usuario, email, hashed_password,False)
        )
        novo_id=cur.fetchone()['id']
        print(f"Novo ID: {novo_id}")
        session['novo_id']=novo_id
        conn.commit()
        cur.close()
        conn.close()
        redirect_uri=f'{url_global}/login'
        return redirect(redirect_uri)      
         # Redirecionar para a página de login

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()




# PESSOA IRA LOGAR CONTA DO MERCADO-LIVRE
@app.route('/login', methods=['GET'])
def login():
    print("Entrou no login")
    user_id=session['novo_id']
    print("encontrou o user_id no /login: ", user_id)

    if not user_id:
        return "Usuário não autenticado", 401

    state = str(uuid.uuid4())
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO verifier (user_id, state, code_verifier) VALUES (%s, %s, %s)",
        (user_id, state, code_verifier)
    )
    conn.commit()
    cur.close()
    conn.close()
    time.sleep(10) 
    session['code_verifier'] = code_verifier 
    auth_url = f"https://auth.mercadolivre.com.br/authorization?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256"
    return redirect(auth_url)



#CALLBACK ONDE AUTENTICAMOS COM SEGURANÇA UM ROTA ENTRE NOVAI E A CONTA DO MERCADO-LIVRE(USUARIO)
@app.route('/callback', methods=['GET'])
def callback():
    state = request.args.get('state')
    code = request.args.get('code')

    if not state or not code:
        return "Parâmetros ausentes", 400
    print("parametros recbidos: ", state, code)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, code_verifier FROM verifier WHERE state = %s", (state,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if not result:
        print("Sessão OAuth não encontrada")
        return "Sessão OAuth não encontrada", 400
    print("result: ", result)
    usuario_id = result['user_id']
    code_verifier = result['code_verifier']

    # Troca do código de autorização pelo token de acesso
    token_url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier
    }

    response = requests.post(token_url, data=payload)
    token_data = response.json()
    print("token_data:",token_data)
    headers = {
    "Authorization": f"Bearer {token_data['access_token']}"
}
    response = requests.get('https://api.mercadolibre.com/users/me', headers=headers)
    response_data = response.json()
    id_ml = response_data.get('id')


    if "access_token" not in token_data:
        print('Erro ao obter o Access Token')
        return "Erro ao obter o Access Token", 400
    else:
        print('users/me ',end=' ')
        resp_user_me =requests.get('https://api.mercadolibre.com/users/me', headers=headers)
        user_me = resp_user_me.json()
        print(user_me)

    # Armazenando informações

    # Calcula a data/hora de expiração do token
    expires_in = token_data["expires_in"]  # em segundos
    expiracao_token = datetime.now() + timedelta(seconds=expires_in)

    # Verifica se o usuario_id foi recuperado e esta autenticado
    print("usuario_id: ", usuario_id)
    print('token:',token_data["access_token"])
    print('expiracao:',expiracao_token)
    print('refresh_token:',token_data.get("refresh_token", ""))
    if not usuario_id:
        print("usuario nao autenticado internamente")
        return jsonify({"error": "Usuário não autenticado internamente"}), 401

    try:
    # Conecta ao banco e obtém o cursor
        conn = get_db_connection()
        cur = conn.cursor()

        # Insere os dados na tabela contas_mercado_livre e retorna o id inserido
        cur.execute(
            """
            INSERT INTO contas_mercado_livre 
            (usuario_id, acess_token, refresh_token, expiracao_token,id_ml)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                usuario_id,
                token_data["access_token"],
                token_data.get("refresh_token", ""),
                expiracao_token,
                id_ml,
            )
        )

        # Deleta o registro da tabela verifier relacionado ao usuário
        cur.execute("DELETE FROM verifier WHERE user_id = %s", (usuario_id,))
        if cur.rowcount == 0:
            print(f"Nenhum registro encontrado para o usuário {usuario_id} na tabela verifier")

        conn.commit()
    except Exception as e:
        conn.rollback()
        print("Ocorreu um erro:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()
        token_jwt=gerar_token(usuario_id)
    print('chegou aqui')
    response = make_response(redirect("https://app.nossopoint-backend-flask-server.com/loading"))
    response = clear_legacy_cookies(response)     # 👈 limpa lixo
    response = set_auth_cookie(response, token_jwt)  # 👈 define só o __Host-token
    return response


@app.route('/webhook/ml/messages', methods=['POST'])
def webhook_mercado_livre_messages():
    data = request.get_json(force=True) or {}
    id_ml = data.get('user_id')
    print("🔔 Notificação de mensagens recebida:", data)
    # 1) Sempre persistir e ACK rápido
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT usuario_id from contas_mercado_livre WHERE id_ml=%s', (id_ml,))
        usuario_id_dict = cur.fetchone()
        user_id = usuario_id_dict['usuario_id']
        cur.execute(
            "INSERT INTO notification (notificacao, topic) VALUES (%s, %s)",
            (json.dumps(data), str(data.get('topic','')))
        )

    # 2) Se há sync em andamento para esse usuário, não processe agora
    if user_id is not None:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s) AS got", (int(user_id),))
            got = cur.fetchone()["got"]
        if not got:
            return jsonify({"status": "queued"}), 202
        # liberar imediatamente (foi só teste de lock)
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(%s)", (int(user_id),))

    # 3) disparar processamento leve em background
    socketio.start_background_task(processar_notificacao_ml, data, user_id)
    return jsonify({"status": "ok"}), 200

def processar_notificacao_ml(data: dict, user_id):
    with app.app_context():
        id_ml = data.get('user_id')
        # tente respeitar exclusividade por usuário
        got_lock = False
        if user_id is not None:
            got_lock = sync_lock_acquire(int(user_id))
            if not got_lock:
                app.logger.info(f"[notif] sync em andamento para {user_id}; notificação já persistida, saindo.")
                return
        try:
            now = datetime.utcnow()

            # renovar token se expirado e pegar credenciais
            with get_db_connection() as conn, conn.cursor() as cur:
                cur.execute("""
                    SELECT expiracao_token, refresh_token
                    FROM contas_mercado_livre
                    WHERE id_ml = %s
                """, (id_ml,))
                row = cur.fetchone()

                if row and row.get("expiracao_token") and now > row["expiracao_token"]:
                    app.logger.info("Token expirado, renovando...")
                    dados = renovar_access_token(row["refresh_token"])
                    cur.execute("""
                        UPDATE contas_mercado_livre
                        SET acess_token=%s,
                            refresh_token=%s,
                            expiracao_token=%s
                        WHERE id_ml=%s
                    """, (dados["access_token"], dados["novo_refresh_token"],
                        dados["nova_expiracao"], id_ml))
                    conn.commit()

                cur.execute("""
                    SELECT acess_token, usuario_id
                    FROM contas_mercado_livre
                    WHERE id_ml = %s
                """, (id_ml,))
                cred = cur.fetchone()

            if not cred:
                app.logger.warning(f"[notif] credenciais não encontradas para id_ml={id_ml}")
                return

            topic = str(data.get('topic',''))

            if topic == 'messages':
                pos_venda_notifications(data, cred, json.dumps(data))
            elif topic == 'questions':
                pre_venda_notifications(data, cred)
            elif topic == 'items':
                itens_notifications(data, cred)
            elif topic == 'orders_v2':
                orders_notifications(data.get('resource', ''), cred, json.dumps(data))
            elif topic == 'public_offers':
                public_offers_notifications(data, cred)
            elif topic == 'post_purchase':
                claims_notifications(data, cred)    
            # elif topic == 'payments':
            #     payments_notifications(data, cred)

        except Exception as e:
            app.logger.exception("Erro no worker de notificação: %s", e)
        finally:
        # Certifique-se de fechar o cursor e a conexão
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()
            if user_id is not None and got_lock:
                sync_lock_release(int(user_id))


def payments_notifications(data, acess_token_data):
    print("🔔 Notificação de envios recebida:", data)
    resource = data.get('resource', '')
    url_shipments = f"https://api.mercadolibre.com{resource}"



def public_offers_notifications(data, acess_token_data):
    try:
        conn= get_db_connection()
        cur = conn.cursor()
        print("🔔 Notificação de ofertas públicas recebida:", data)
        resource=data.get('resource', '')
        url_offers = f"https://api.mercadolibre.com{resource}"
        headers = {"Authorization": f"Bearer {acess_token_data['acess_token']}"}
        response = requests.get(url_offers, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        offer_data = response.json()
        item_id = offer_data.get('item_id')
        
        promotion_id = offer_data.get('promotion_id')
        user_id = acess_token_data['usuario_id']
        
        cur.execute("SELECT * FROM ponte_item_promotions WHERE AND promotion_id = %s", (promotion_id,))
        existing_offers = cur.fetchone()
        url_promocao = f'https://api.mercadolibre.com/seller-promotions/promotions/{promotion_id}?promotion_type={type_promotion}&app_version=v2'
        response = requests.get(url_promocao, headers=headers)
        if response.status_code not in [200]:
            print(f"Erro ao consultar promoções")
            return
        resposta = response.json()
        id_promotion = resposta.get('id', None)
        type_promotion = resposta.get('type', None)
        status = resposta.get('status', None)
        finish_date = resposta.get('finish_date')
        start_date = resposta.get('start_date', None)
        deadline = resposta.get('deadline_date', None)
        name = resposta.get('name', None)
        cur.execute('INSERT INTO promotion (id_promotion,type_promotion,status,finish_date,start_date,deadline_date,name, usuario_id_promotions) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',(id_promotion, type_promotion, status, finish_date, start_date, deadline, name,user_id,))
        conn.commit()
        if type_promotion == 'MARKET_PLACE_CAMPAIGN':
            benefits = resposta.get('benefits', {})
            if benefits:
                meli_percent = benefits.get('meli_percent', None)
                seller_percent = benefits.get('seller_percent', None)
                benefits_type = benefits.get('type', None)
                if existing_offers:
                    print("Oferta já existe, atualizando dados.")
                    cur.execute('''UPDATE market_place_campaign_type_promotion SET type_promotion = %s,
                    type_benefits = %s,meli_percent = %s,seller_percent = %s WHERE id_promotion = %s AND usuario_id_marketplace_campaign_type_promotion = %s''',
                    (type_promotion,benefits_type,meli_percent,seller_percent,id_promotion,user_id))
                else:
                    print("Oferta não existe, inserindo dados.")
                    cur.execute('INSERT INTO market_place_campaign_type_promotion (id_promotion, type_promotion, type_benefits, meli_percent,seller_percent,usuario_id_marketplace_campaign_type_promotion) VALULES (%s,%s,%s,%s,%s,%s)',(id_promotion, type_promotion, benefits_type, meli_percent, seller_percent,user_id,))
    
        elif type_promotion == 'PRE_NEGOTIATED' or type_promotion == 'UNHEALTHY_STOCK':
            offers = resposta.get('offers',[])
            for offer in offers:
                offer_id = offer.get('id', None)
                original_price = offer.get('original_price', None)
                new_price = offer.get('new_price', None)
                status_offer = offer.get('status', None)
                start_date_offer = offer.get('start_date', None)
                end_date_offer = offer.get('end_date', None)
                benefits = offer.get('benefits', {})
                meli_percent = benefits.get('meli_percent', None)
                seller_percent = benefits.get('seller_percent', None)
                benefits_type = benefits.get('type', None)
                if existing_offers:
                    print("Oferta já existe, atualizando dados.")
                    cur.execute('''UPDATE pre_negotiated_type_promotion SET type_promotion = %s,offer_id = %s,
                    type_benefits = %s,meli_percent = %s,seller_percent = %s,start_date = %s,end_date = %s,status = %s,
                    original_price = %s,new_price = %s WHERE id_promotion = %s AND usuario_id_pre_negotiated_type_promotion_offers = %s''',
                    (type_promotion,offer_id,benefits_type,meli_percent,seller_percent,start_date_offer,end_date_offer,status_offer,
                    original_price,new_price,id_promotion,user_id))
                else:
                    cur.execute('''INSERT INTO pre_negotiated_type_promotion (id_promotion,type_promotion, 
                    offer_id,type_benefits, meli_percent, seller_percent, start_date, end_date, status, 
                    original_price, new_price, usuario_id_pre_negotiated_type_promotion_offers) 
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(id_promotion,type_promotion, offer_id, benefits_type, meli_percent, seller_percent, start_date_offer, end_date_offer, status_offer, original_price, new_price,user_id,))
        elif type_promotion == 'SELLER_COUPON_CAMPAIGN':
            sub_type = resposta.get('sub_type', None)
            fixed_amount = resposta.get('fixed_amount', None)
            min_purchase_amount = resposta.get('min_purchase_amount',None)
            max_purchase_amount = resposta.get('max_purchase_amount', None)
            coupon_code = resposta.get('coupon_code', None)
            redeems_per_user = resposta.get('redeems_per_user', None)
            budget = resposta.get('budget',None)
            remaining_budget = resposta.get('remaining_budget', None)
            used_coupons = resposta.get('used_coupons', None)
            fixed_percentage = resposta.get('fixed_percentage', None)
            if existing_offers:
                print("Oferta já existe, atualizando dados.")
                cur.execute('''UPDATE seller_coupon_type_promotion SET type_promotion = %s, sub_type = %s,
                fixed_amount = %s,min_purchase_amount = %s,max_purchase_amount = %s,
                coupon_code = %s,redeems_per_user = %s,budget = %s,remaining_budget = %s,used_coupons = %s,fixed_coupons = %s WHERE
                id_promotion = %s AND usuario_id_seller_coupon_type_promotion = %s''',(type_promotion,sub_type,fixed_amount,min_purchase_amount,
                max_purchase_amount,coupon_code,redeems_per_user,budget,remaining_budget,used_coupons,fixed_percentage,id_promotion,user_id))
            else:
                print("Oferta não existe, inserindo dados.")
                cur.execute('''INSERT INTO seller_coupon_type_promotion (id_promotion,type_promotion,sub_type, fixed_amount, min_purchase_amount, max_purchase_amount, coupon_code, redeems_per_user,
                budget, remaining_budget, used_coupons, fixed_coupons, usuario_id_seller_coupon_type_promotion) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(id_promotion,type_promotion,sub_type,
                fixed_amount,min_purchase_amount,max_purchase_amount,coupon_code,redeems_per_user, budget, remaining_budget, used_coupons, fixed_percentage, user_id,))
    
        elif type_promotion == 'VOLUME':
            buy_quantity = resposta.get('buy_quantity', None)
            pay_quantity= resposta.get('pay_quantity', None)
            allow_combination = resposta.get('allow_combination', None)
            sub_type = resposta.get('sub_type', None)
            if existing_offers:
                print("Oferta já existe, atualizando dados.")
                cur.execute('''UPDATE volume_type_promotion SET type_promotion = %s,buy_quantity = %s,pay_quantity = %s,sub_type = %s,
                allow_combination = %s WHERE id_promotion = %s AND usuario_id_volume_type_promotion = %s''',(type_promotion,buy_quantity,
                pay_quantity,sub_type,allow_combination,id_promotion,user_id))
            else:
                print("Oferta não existe, inserindo dados.")
                cur.execute('''INSERT INTO volume_type_promotion (id_promotion,type_promotion,buy_quantity, pay_quantity, sub_type, allow_combination, usuario_id_volume_type_promotion) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                (id_promotion, type_promotion, buy_quantity, pay_quantity, sub_type, allow_combination, user_id ,))
        url=f'https://api.mercadolibre.com/seller-promotions/promotions/{id_promotion}/items?promotion_type={type_promotion}&item_id={item_id}&app_version=v2'
        response = requests.get(url, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        item_promotion_data = response.json()
        results = item_promotion_data.get('results', [])
        if not results:
            print("Nenhum item encontrado na promoção.")
            return jsonify({"error": "Nenhum item encontrado na promoção"}), 404
        cur.execute("SELECT * FROM ponte_item_promotions WHERE promotion_id = %s AND item_id = %s AND usuario_id_ponte_item_promotions=%s", (id_promotion, item_id, user_id,))
        existing_item_promotion = cur.fetchone()
        for result in results:
            id_promotion_item = id_promotion
            item_id = result.get('id', None)
            cur.execute('SELECT nome_item from itens where item_id = %s',(item_id,))
            nome_item_dict = cur.fetchone()
            nome_item = nome_item_dict.get('nome_item', None)
            status = result.get('status', None)
            price = result.get('price', None)
            original_price = result.get('original_price', None)
            min_discounted_price= result.get('min_discounted_price', None)
            max_discounted_price= result.get('max_discounted_price', None)
            suggested_discounted_price= result.get('suggested_discounted_price', None)
            start_date= result.get('start_date', None)
            end_date = result.get('end_date', None)
            sub_type = result.get('sub_type', None)
            offer_id = result.get('offer_id', None)
            meli_percentage = result.get('meli_percentage', None)
            seller_percentage = result.get('seller_percentage', None)
            buy_quantity = result.get('buy_quantity', None)
            pay_quantity = result.get('pay_quantity', None)
            allow_combination = result.get('allow_combination', None)
            fixed_amount = result.get('fixed_amount', None)
            fixed_percentage = result.get('fixed_percentage', None)
            top_deal_price = result.get('top_deal_price', None)
            discount_percentage = result.get('descount_percentage', None)
            if existing_item_promotion:
                cur.execute("""UPDATE ponte_item_promotions SET status = %s,price = %s,original_price = %s,min_discounted_price = %s,max_discounted_price = %s,
                suggested_discounted_price = %s,start_date = %s,end_date = %s,sub_type = %s,offer_id = %s,meli_percentage = %s,seller_percentage = %s,
                buy_quantity = %s,pay_quantity = %s,allow_combination = %s,fixed_amount = %s,fixed_percentage = %s,top_deal_price = %s,
                discount_percentage = %s,nome_item=%s, auto=%s WHERE id_promotion = %s AND item_id = %s AND usuario_id_ponte_item_promotions = %s""",(status,price,original_price,
                min_discounted_price,max_discounted_price,suggested_discounted_price,start_date,end_date,sub_type,offer_id,meli_percentage,seller_percentage,
                buy_quantity,pay_quantity,allow_combination,fixed_amount,fixed_percentage,top_deal_price,discount_percentage,nome_item,False,id_promotion_item,item_id,user_id))
    
            else:
                cur.execute("""INSERT INTO ponte_item_promotions (id_promotion, item_id, status, price, original_price, 
                                    min_discounted_price,max_discounted_price, suggested_discounted_price, start_date, end_date, sub_type, offer_id, meli_percentage, 
                                    seller_percentage, buy_quantity, pay_quantity, allow_combination, fixed_amount, fixed_percentage, top_deal_price, 
                                    discount_percentage,nome_item, usuario_id_ponte_item_promotions,auto) VALUES (%s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s,%s,%s)""",(id_promotion_item, item_id, status, price, original_price, 
                                    min_discounted_price,max_discounted_price ,suggested_discounted_price, start_date, end_date,sub_type, offer_id, meli_percentage, 
                                    seller_percentage, buy_quantity, pay_quantity, allow_combination, fixed_amount, fixed_percentage, top_deal_price, 
                                    discount_percentage, nome_item, user_id,False))
    except Exception as e:
        print("Erro nas notificacao das promocoes: ", str(e))
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()



import unicodedata
from bs4 import BeautifulSoup, SoupStrainer

# ----------------- HTTP (pooling + retries) -----------------
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

UA_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126 Safari/537.36",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SESSION = requests.Session()
_retries = Retry(
    total=3, backoff_factor=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET", "HEAD", "OPTIONS"),
)
SESSION.mount("https://", HTTPAdapter(max_retries=_retries, pool_connections=20, pool_maxsize=50))
SESSION.mount("http://",  HTTPAdapter(max_retries=_retries, pool_connections=20, pool_maxsize=50))

# ----------------- Utils -----------------
SOLD_RE = re.compile(
    r'(?:mais\s+de\s+)?\+?\s*([\d.,]+)\s*(mil(?:h(?:ão|oes))?|milhões?|mil|k|m)?\s*vendid[oa]s',
    re.I
)
CLS_SUBTITLE = re.compile(r"(?:^|\s)ui-pdp-subtitle(?:\s|$)", re.I)

from urllib.parse import urlparse, parse_qs,urljoin,urlencode, quote

MLB8_RE  = re.compile(r"\bMLB(\d{8})\b")
MLB10_RE = re.compile(r"\bMLB(\d{10})\b")

def _slugify_item_name(name: str) -> str:
    """
    Converte o nome do item em slug:
    - Remove completamente letras acentuadas (ex: 'á' → '').
    - Remove qualquer caractere não alfanumérico (., -, _, +, =, etc).
    - Tudo minúsculo.
    - Junta blocos válidos com hífen.
    Exemplo:
      "Kit 2câmera Ip Icsee Prova D'água Infravermelho Externa Wifi - HW"
      -> "kit-2cmera-ip-icsee-prova-dagua-infravermelho-externa-wifi-hw"
    """
    if not name:
        return ""

    # normaliza e remove acentos
    name = unicodedata.normalize("NFD", name)
    # remove caracteres com marca diacrítica (acentos)
    name = "".join(ch for ch in name if unicodedata.category(ch) != "Mn")

    # remove TUDO que não for letra ou número
    name = re.sub(r"[^a-zA-Z0-9\s]", " ", name)

    # deixa minúsculo
    name = name.lower().strip()

    # troca qualquer sequência de espaços por hífen
    slug = re.sub(r"\s+", "-", name)

    return slug

def _resolve_meli_url(url: str, item_name: str) -> str:
    """
    Transforma tracking-links 'click*.mercadolivre.com.br/mclics/clicks/external/...'
    no permalink PDP no formato:
      https://www.mercadolivre.com.br/{slug}/p/MLB########?pdp_filters=item_id:MLB##########
    Onde:
      - MLB########   => MLB + 8 dígitos (ex.: searchVariation=MLB46836439)
      - MLB########## => MLB + 10 dígitos (ex.: wid=MLB5309063322)
    Se não for tracking-link OU não encontrar os dois IDs, retorna a url original.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        # só processa se for tracking dos cliques
        if not (host.startswith("click") and "/mclics/clicks/external/" in path):
            return url

        # procure MLB de 8 e 10 dígitos em toda a URL (path + query + fragment)
        haystack = f"{parsed.path}?{parsed.query}#{parsed.fragment}"

        m8  = MLB8_RE.search(haystack)
        m10 = MLB10_RE.search(haystack)

        if not (m8 and m10):
            # se não achou ambos, não arrisca – mantém original
            return url

        mlb8  = f"MLB{m8.group(1)}"
        mlb10 = f"MLB{m10.group(1)}"

        slug = _slugify_item_name(item_name)

        # monta o permalink final
        final_url = (
            f"https://www.mercadolivre.com.br/{slug}/p/{mlb8}"
            f"?pdp_filters=item_id:{mlb10}"
        )
        return final_url

    except Exception:
        return url

def _resolve_meli_url_up(url: str, item_name: str) -> str:
    """
    Transforma tracking-links 'click*.mercadolivre.com.br/mclics/clicks/external/...'
    no permalink PDP no formato:
      https://www.mercadolivre.com.br/{slug}/p/MLB########?pdp_filters=item_id:MLB##########
    Onde:
      - MLB########   => MLB + 8 dígitos (ex.: searchVariation=MLB46836439)
      - MLB########## => MLB + 10 dígitos (ex.: wid=MLB5309063322)
    Se não for tracking-link OU não encontrar os dois IDs, retorna a url original.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        # só processa se for tracking dos cliques
        if not (host.startswith("click") and "/mclics/clicks/external/" in path):
            return url

        # procure MLB de 8 e 10 dígitos em toda a URL (path + query + fragment)
        haystack = f"{parsed.path}?{parsed.query}#{parsed.fragment}"

        m8  = MLB8_RE.search(haystack)
        m10 = MLB10_RE.search(haystack)

        if not (m8 and m10):
            # se não achou ambos, não arrisca – mantém original
            return url

        mlb8  = f"MLB{m8.group(1)}"
        mlb10 = f"MLB{m10.group(1)}"

        slug = _slugify_item_name(item_name)

        # monta o permalink final
        final_url = (
            f"https://www.mercadolivre.com.br/{slug}/up/{mlb8}"
            f"?pdp_filters=item_id:{mlb10}"
        )
        return final_url

    except Exception:
        return url

def _normalize(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    s = re.sub(r"\s+", " ", s.lower()).strip()
    return s

def _parse_sold_from_text(txt: str) -> Optional[int]:
    if not txt:
        return None
    m = SOLD_RE.search(txt)
    if not m:
        return None
    base = m.group(1).replace(".", "").replace(",", ".")
    try:
        num = float(base)
    except ValueError:
        return None
    suf = (m.group(2) or "").lower()
    if suf.startswith("milh") or suf == "m":
        num *= 1_000_000
    elif suf.startswith("mil") or suf == "k":
        num *= 1_000
    return int(round(num))

def _extract_subtitle_and_sold(html: str) -> Tuple[str, int]:
    """
    Retorna (subtitle_text, sold_int).
    - Tenta aria-label do span.ui-pdp-subtitle
    - Cai para texto interno
    - Fallback: qualquer trecho contendo 'vendid'
    """
    if not html:
        return ("", 0)

    # parse somente <span class="ui-pdp-subtitle"> para ser rápido
    only_subtitle_spans = SoupStrainer("span", class_=CLS_SUBTITLE)
    soup = BeautifulSoup(html, "lxml", parse_only=only_subtitle_spans)

    subtitle_el = soup.find("span", class_=CLS_SUBTITLE)
    subtitle_text = ""

    if subtitle_el:
        subtitle_text = (subtitle_el.get("aria-label") or
                         subtitle_el.get_text(" ", strip=True) or "").strip()

    sold = _parse_sold_from_text(subtitle_text)

    # Fallback 1: se não veio no aria-label, tenta o próprio texto interno
    if sold is None and subtitle_el:
        inner = subtitle_el.get_text(" ", strip=True)
        sold = _parse_sold_from_text(inner)

    # Fallback 2: varre um pouco do HTML procurando 'vendid'
    if sold is None:
        any_text = BeautifulSoup(html, "lxml").get_text(" ", strip=True)
        chunk = None
        m = re.search(r"(.{0,60}vendid.{0,60})", any_text, flags=re.I)
        if m:
            chunk = m.group(1)
        if chunk:
            sold = _parse_sold_from_text(chunk)

    return (subtitle_text, int(sold or 0))

def _slugify_keep_letters(name: str) -> str:
    """
    Variante 'soft' do slugify: mantém as letras com acentos,
    apenas removendo o acento e caracteres especiais.
    """
    if not name:
        return ""

    name = unicodedata.normalize("NFD", name)
    name = "".join(ch for ch in name if unicodedata.category(ch) != "Mn")  # tira acento
    name = re.sub(r"[^a-zA-Z0-9\s]", " ", name)  # remove especiais, mantém letras
    name = name.lower().strip()
    slug = re.sub(r"\s+", "-", name)
    return slug

@app.route("/scraping", methods=["POST"])
def scraping():
    try:
        data = request.get_json(force=True) or {}
        items: List[Dict[str, Any]] = data.get("items") or []
        print('items: ', items)
        print('tamanho da lista: ', len(items))
        cookie_header: str = data.get("cookie") or ""  # cookies do body (string "k=v; k2=v2")

        result_map: Dict[str, Any] = {}

        # headers base (permite Cookie por request)
        base_headers = UA_HEADERS.copy()
        if cookie_header:
            base_headers["Cookie"] = cookie_header  # mantém cookies

        for it in items:
            item_id = (it.get("item_id") or it.get("itemId") or "").strip()
            url = (it.get("url") or "").strip()
            item_name = (it.get("item_name") or "")
            if not item_id or not url:
                continue

            # Valores default seguros
            final_url = _resolve_meli_url(url, item_name)
            subtitle_text, sold = "", None

            try:
                resp = SESSION.get(final_url, headers=base_headers, timeout=12)
                resp.raise_for_status()
                html = resp.text
                subtitle_text, sold = _extract_subtitle_and_sold(html)
            except Exception as e:
                print(f"[Erro primário] {final_url}: {e}")

            # Fallback 1: slug "soft"
            if not subtitle_text:
                alt_slug = _slugify_keep_letters(item_name)
                final_url2 = _resolve_meli_url(url, alt_slug)
                if final_url2 != final_url:
                    print(f"[Fallback slug soft] Tentando novamente com: {final_url2}")
                    try:
                        resp2 = SESSION.get(final_url2, headers=base_headers, timeout=12)
                        resp2.raise_for_status()
                        html2 = resp2.text
                        subtitle_text2, sold2 = _extract_subtitle_and_sold(html2)
                        if subtitle_text2:
                            subtitle_text, sold, final_url = subtitle_text2, sold2, final_url2
                        else:
                            print(f"[Fallback slug soft] Ainda sem subtítulo em {final_url2}")
                    except Exception as e:
                        print(f"[Erro fallback soft] {final_url2}: {e}")

            # Fallback 2: _resolve_meli_url_up com item_name
            if not subtitle_text:
                try:
                    final_url3 = _resolve_meli_url_up(url, item_name)
                    print(f"[Fallback up 1] Tentando: {final_url3}")
                    resp3 = SESSION.get(final_url3, headers=base_headers, timeout=12)
                    resp3.raise_for_status()
                    html3 = resp3.text
                    subtitle_text3, sold3 = _extract_subtitle_and_sold(html3)
                    if subtitle_text3:
                        subtitle_text, sold, final_url = subtitle_text3, sold3, final_url3
                    else:
                        print(f"[Fallback up 1] Ainda sem subtítulo em {final_url3}")
                except Exception as e:
                    print(f"[Erro fallback up 1] {e}")

            # Fallback 3: _resolve_meli_url_up com slug
            if not subtitle_text:
                try:
                    alt_slug4 = _slugify_keep_letters(item_name)
                    final_url4 = _resolve_meli_url_up(url, alt_slug4)
                    print(f"[Fallback up 2] Tentando: {final_url4}")
                    resp4 = SESSION.get(final_url4, headers=base_headers, timeout=12)
                    resp4.raise_for_status()
                    html4 = resp4.text
                    subtitle_text4, sold4 = _extract_subtitle_and_sold(html4)
                    if subtitle_text4:
                        subtitle_text, sold, final_url = subtitle_text4, sold4, final_url4
                    else:
                        print(f"[Fallback up 2] Ainda sem subtítulo em {final_url4}")
                except Exception as e:
                    print(f"[Erro fallback up 2] {e}")

            # Monta resposta do item (de preferência com a URL realmente utilizada)
            result_map[item_id] = {
                "url": url,
                "subtitle": subtitle_text,  # ex: "Novo · +1000 vendidos"
                "sold": sold                # inteiro já normalizado ou None
            }

        print('result_map: ', result_map)
        return jsonify(result_map), 200

    except Exception as e:
        print("Erro /scraping:", str(e))
        return jsonify({"error": str(e)}), 500




@app.route('/visitsItems', methods=['POST'])
def visitsItems():
    data = request.get_json()
    itemId=data['itemId']
    print("Buscando visualizações...")
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT acess_token FROM contas_mercado_livre LIMIT 1")
        token_dict=cur.fetchone()
        token=token_dict['acess_token']
    url = f"https://api.mercadolibre.com/visits/items?ids={itemId}"
    response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    print("Status:", response.status_code)
    print(response.json())
    resposta= response.json()
    return jsonify({'itemId':resposta[itemId]}),200

@app.route('/visitas_por_mes', methods=['POST'])
def visitas_por_mes():
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT acess_token FROM contas_mercado_livre LIMIT 1')
        acess_token_dict = cur.fetchone()
        token = acess_token_dict['acess_token']
    data = request.get_json()
    conversion = data.get('conversion')
    item = data.get('item_id')
    price = data.get('price', 0)
    print("Buscando visualizações...")
    total_visits_mes=0
    date_to= datetime.now().strftime('%Y-%m-%d')
    meses = []
    meses_data=[]
    faturamentos = []
    quantityMounth=[]
    for i in range(0,24):
        date_from= (datetime.now() - timedelta(days=(i+1)*30)).strftime('%Y-%m-%d')
        date_to= (datetime.now() - timedelta(days=i*30)).strftime('%Y-%m-%d')
        url_por_mes= f'https://api.mercadolibre.com/items/visits?ids={item}&date_from={date_from}&date_to={date_to}'
        response = requests.get(url_por_mes, headers={"Authorization": f"Bearer {token}"})
        visitas=response.json()
        print(f'Mês: {date_from}', end=' ')
        total_visits_mes=int(visitas[0]['total_visits'])
        meses.append(total_visits_mes)
        meses_data.append({"date_from":date_from,"date_to":date_to})
        faturamentos.append(int(total_visits_mes * (conversion/100))*price)
        quantityMounth.append(int(total_visits_mes * (conversion/100)))
        print(f'{i+1}: ',total_visits_mes)
    for i, mes in reversed(list(enumerate(meses))):
        if mes > 0:
            data_date=meses_data[i]
            data_from=data_date['date_from']
            data_to=data_date['date_to']
            data_criacao_item=procurar_data_inicial(item,data_from,data_to,token)
            print('data_criacao do item: ',data_criacao_item)
            return {'meses': meses, 'faturamentos': faturamentos, 'data_criacao':data_criacao_item,'quantityMonths':quantityMounth}
    print("Status:", response.status_code)
    return {'meses': meses, 'faturamentos': faturamentos, 'data_criacao':None, 'quantityMonths':quantityMounth}

def procurar_data_inicial(item_id, data_from,data_to,token):
    try:
        for i in range(30):
            start = datetime.strptime(data_from, "%Y-%m-%d") + timedelta(days=i)
            end = start + timedelta(days=1)
            df = start.strftime('%Y-%m-%d')
            dt= end.strftime('%Y-%m-%d')
            print('Procurando visitas do dia: ',df)
            url_por_mes= f'https://api.mercadolibre.com/items/visits?ids={item_id}&date_from={df}&date_to={dt}'
            resposta_final = requests.get(url_por_mes, headers={"Authorization": f"Bearer {token}"})
            visitas_dia=resposta_final.json()
            print(f'Total de visitas do dia[{df}]: {visitas_dia[0]["total_visits"]}')
            if visitas_dia[0]['total_visits']>0:
                print('dia que as visitas iniciaram: ', df)
                return df
        df=None
        return df
    except Exception as e:
        print('Erro', str(e))

def claims_notifications(data, acess_token_data):
    try:
        print("🔔 Notificação de reclamações recebida:", data)
        conn= get_db_connection()
        cur = conn.cursor()
        resource = data.get('resource', '')
        url_claims = f"https://api.mercadolibre.com{resource}"
        headers= {"Authorization": f"Bearer {acess_token_data['acess_token']}"} 
        response = requests.get(url_claims, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        claim_data = response.json() 
        print('claim_data:', claim_data)
        claim_id = claim_data.get('id')
        resource= claim_data.get('resource')
        resource_id=claim_data.get('resource_id')
        status= claim_data.get('status')
        tipo= claim_data.get('type')
        stage= claim_data.get('stage')
        parent_id= claim_data.get('parent_id')
    
        if resource=='order':
            order_id=claim_data.get("resource_id")
            cur.execute("SELECT pack_id FROM pedidos_resumo WHERE id_order=%s",(order_id,))
            pack_id_dict = cur.fetchone()
            pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
        elif resource=='shipment':
            print('shipment')
            url_order_shipment=f"https://api.mercadolibre.com/shipments/{claim_data.get('resource_id', 0)}/items"
            response_order_shipment = requests.get(url_order_shipment, headers=headers)
            if response_order_shipment.status_code in [200,206]:
                order_data = response_order_shipment.json()
                order_id = order_data[0].get("order_id")
                print("Order ID:", order_id)
                cur.execute("SELECT pack_id FROM pedidos_resumo WHERE id_order=%s",(order_id,))
                pack_id_dict = cur.fetchone()
                pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
                print(f"Pack ID encontrado: {pack_id}")
        else:
            pack_id= None
    
        reason_id = claim_data.get('reason', None)
        fulfilled= claim_data.get('fulfilled', False)
        quantity_type= claim_data.get('quantity_type', None)
        site_id= claim_data.get('site_id', None)
        date_created= claim_data.get('date_created', None)
        last_updated= claim_data.get('last_updated', None)
        comprador_id = None
        vendedor_id = None
        acoes_disponiveis = []
    
        players = claim_data.get("players", [])
        for player in players:
            if player["role"] == "complainant" and player["type"] == "buyer":
                comprador_id = player["user_id"]
            if player["role"] == "respondent" and player["type"] == "seller":
                vendedor_id = player["user_id"]
                acoes_disponiveis = [acao["action"] for acao in player.get("available_actions", [])]
        resolution = claim_data.get("resolution", {})
        if resolution:
            reason_resolution = resolution.get("reason", None)
            date_resolution = resolution.get("date", None)
            benefited = resolution.get("benefited",[]) 
            resolution_closed_by = resolution.get("closed_by", None)
            applied_coverage = resolution.get("applied_coverage", False)
            print("Motivo da resolução:", reason_resolution)
            print("Data da resolução:", date_resolution)
            print("Beneficiado:", benefited)
            print("Resolução fechada por:", resolution_closed_by)
            print("Cobertura aplicada:", applied_coverage)
        url_reason = f"https://api.mercadolibre.com/post-purchase/v1/claims/reasons/{reason_id}"
        response_reason = requests.get(url_reason, headers=headers)
        if response_reason.status_code != 200:
            print(f"❌ Erro ao buscar razão da reclamação {claim_id}: {response_reason.status_code}")
            reason = None
            nome_reason = None
            expected_solution = []
        else:
            reason_data = response_reason.json()
            #print(f'reason_data: {reason_data}')
            nome_reason = reason_data.get("name")
            #print(f"Nome da razão: {nome_reason}")
            settings = reason_data.get("settings", {})
            expected_solution = settings.get('expected_resolutions', [])
            print("Nome da razão:", nome_reason)
            print("Soluções esperadas:", expected_solution)
    
        #print('--------------------------------')
        url_details = f"https://api.mercadolibre.com/post-purchase/v1/claims/{claim_id}/detail"
        response_details = requests.get(url_details, headers=headers)
    
        if response_details.status_code != 200:
            print(f"❌ Erro ao buscar detalhes da reclamação {claim_id}: {response_details.status_code}")
            title = None
            due_date_detail = None
            description = None
            action_responsible = None
            problem= None
        else:
            details = response_details.json()
            #print(f'Details: {details}')
            title = details.get("title")
            due_date_detail = details.get("due_date")
            description = details.get("description")
            action_responsible = details.get("action_responsible")
            problem= details.get("problem")
            print("Problema:", problem)
            print("description:", description)
            print("due_date_detail:", due_date_detail)
            print("Title:", title)
            print("Action responsible:", action_responsible)
        print("ID da reclamação:", claim_id)
        print("resource_id:", resource_id)
        print("status:", status)
        print("tipo:", tipo)
        print("stage:", stage)
        print("parent_id:", parent_id)
        print("order_id:", order_id)
        print("pack_id:", pack_id)
        print("fulfilled:", fulfilled)
        print("quantity_type:", quantity_type)
        print("site_id:", site_id)
        print("date_created:", date_created)
        print("last_updated:", last_updated)
        print("ID do comprador:", comprador_id)
        print("ID do vendedor:", vendedor_id)
        print("Ações disponíveis:", acoes_disponiveis)
        cur.execute("SELECT * FROM reclamacoes WHERE claim_id = %s", (claim_id,))
        existing_claim = cur.fetchone()
        if existing_claim:
            print("Reclamação já existe, atualizando dados.")
            cur.execute("SELECT * FROM reclamacoes WHERE claim_id = %s", (claim_id,))
            data_reclamacao = cur.fetchone()
            print("Dados da reclamação existente:", data_reclamacao)
            cur.execute("""UPDATE reclamacoes SET resource_id = %s, resource=%s,status = %s, tipo = %s, stage = %s, parent_id = %s, pack_id = %s, reason_id = %s,
                        fulfilled = %s, quantity_type = %s, site_id = %s, date_created = %s, last_updated = %s,
                        comprador_id = %s, vendedor_id = %s, acoes_disponiveis=%s,name_reason=%s,expected_solutions=%s,problem=%s,
                        description=%s,due_date=%s,title=%s,action_responsible=%s WHERE claim_id = %s AND usuario_id_reclamacoes=%s""",
                        (resource_id,resource, status, tipo, stage, parent_id, pack_id, reason_id,
                         fulfilled, quantity_type, site_id, date_created, last_updated,
                         comprador_id, vendedor_id, acoes_disponiveis,nome_reason,expected_solution,
                         problem, description,due_date_detail,title,action_responsible,
                         claim_id, acess_token_data['usuario_id']))
        else:
            print("Reclamação não existe, inserindo dados.")
            cur.execute('''
                        INSERT INTO reclamacoes (
                            claim_id, resource_id, status, tipo, stage, parent_id, pack_id, reason_id,
                        fulfilled, quantity_type, site_id, date_created, last_updated,
                            comprador_id, vendedor_id, acoes_disponiveis,name_reason,expected_solutions,problem,description,due_date,title,action_responsible,usuario_id_reclamacoes,resource
                        )
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (claim_id) DO NOTHING
                    ''', (
                    claim_id, resource_id, status, tipo, stage, parent_id, pack_id, reason_id,
                    fulfilled, quantity_type, site_id, date_created, last_updated,
                    comprador_id, vendedor_id, acoes_disponiveis,nome_reason,expected_solution,problem, description, due_date_detail,title,action_responsible,acess_token_data['usuario_id'],resource,
                    ))
        conn.commit()
        conn.close()
        cur.close()
    except Exception as e:
        print("Erro nas notificacao das reclamacoes(claims): ", str(e))
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def orders_notifications(resource,acess_token, data_ant):
    print("🔔 Notificação de pedidos recebida:", resource)
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        headers = {"Authorization": f"Bearer {acess_token['acess_token']}"}
        url = f"https://api.mercadolibre.com/{resource}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        order_data = response.json()
        print('order_data:', order_data)
        id = order_data.get('id')
        cur.execute("SELECT id_order FROM pedidos_resumo WHERE id_order = %s", (id,))
        existing_order = cur.fetchone()
        date_created_z = order_data.get('date_created', None)
        date_created=converter_zona_pro_brasil(date_created_z)
        date_closed_z = order_data.get('date_closed', None)
        date_closed=converter_zona_pro_brasil(date_closed_z)
        last_updated_z = order_data.get('last_updated', None)
        last_updated=converter_zona_pro_brasil(last_updated_z)
        total_amount = order_data.get('total_amount', None)
        paid_amount = order_data.get('paid_amount', None)


        order_data_payments = order_data.get('payments', [])
        payments = order_data_payments[0] 
        status = payments.get('status', None)
        date_approved_z = payments.get('date_approved', None)
        date_approved=converter_zona_pro_brasil(date_approved_z)
        shipping_cost = payments.get('shipping_cost', None)
        payment_method = payments.get('payment_method_id', None)
        payment_type = payments.get('payment_type', None)
        installments = payments.get('installments', None)
        installment_amount = payments.get('installment_amount', None)

        order_data_orders = order_data.get('order_items', [])
        order_items = order_data_orders[0] if order_data_orders else {}
        items = order_items.get('item',{})
        item_id = items.get('id', None)
        item_title = items.get('title', None)
        item_warranty = items.get('warranty', None)
        listing_type_id = items.get('listing_type_id', None)
        category_id = items.get('category_id', None)
        unit_price = items.get('unit_price', None)
        sale_fee = items.get('sale_fee', None)
        quantity = order_items.get('quantity', None)

        buyer_id = order_data.get('buyer', {}).get('id', None)
        tags = order_data.get('tags', [])
        fulfilled = order_data.get('fulfilled', False)
        pack_id = order_data.get('pack_id', None)
        if not pack_id:
            pack_id = id
        if category_id:
            url_categoria=f"https://api.mercadolibre.com/categories/{category_id}"
            response= requests.get(url_categoria, headers=headers)
            if response.status_code in [200, 206]:
                categoria_data = response.json()
                category_name = categoria_data.get('name', 'Sem nome de categoria')
                print(f"Categoria ID: {category_id}, Nome da Categoria: {category_name}")
        else:
            category_name = 'Sem nome de categoria'

        if existing_order:
            print("Pedido já existe, atualizando dados.")
            cur.execute("SELECT * FROM pedidos_resumo WHERE id_order = %s", (id,))
            data_pedidos_resumo = cur.fetchone()
            print("Dados do pedido existente:", data_pedidos_resumo)
            cur.execute("""UPDATE pedidos_resumo SET date_created = %s, date_closed = %s, date_approved = %s, last_updated = %s, 
                        total_amount = %s, paid_amount = %s, status = %s, shipping_cost = %s, payment_method = %s, payment_type = %s, installments = %s,
                    installment_amount = %s, item_id = %s, nome_item = %s, item_warranty = %s, listing_type_id = %s, category_name = %s, unit_price = %s, sale_fee = %s, quantity = %s, buyer_id = %s,
                    tags = %s, fulfilled = %s, pack_id = %s WHERE id_order = %s AND usuario_id_pedidos_resumo=%s""", (date_created, date_closed, date_approved, last_updated, total_amount, paid_amount, 
                    status, shipping_cost, payment_method, payment_type, installments, installment_amount, item_id, item_title, item_warranty, listing_type_id, category_name, unit_price, sale_fee,
                    quantity, buyer_id, tags, fulfilled, pack_id, id, acess_token['usuario_id'],))
            cur.execute("UPDATE notification SET dados_retornados_api = %s, especificacao = %s WHERE notificacao = %s", (json.dumps(order_data), 'dados_existentes',data_ant,))
        else:
            print("Pedido não existe, inserindo novo registro.")
            cur.execute("INSERT INTO packs (pack_id, usuario_id_packs) VALUES (%s, %s) ON CONFLICT (pack_id) DO NOTHING", (pack_id, acess_token['usuario_id'],))
            conn.commit()
            cur.execute("""INSERT INTO pedidos_resumo (id_order, date_created, date_closed, date_approved, last_updated, total_amount, paid_amount, status, shipping_cost,
                        payment_method, payment_type, installments, installment_amount, item_id, nome_item, item_warranty, listing_type_id, category_id, unit_price, sale_fee, 
                        quantity, buyer_id, tags, fulfilled, pack_id, category_name, usuario_id_pedidos_resumo) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (id, date_created, date_closed, date_approved, last_updated, total_amount, paid_amount, status, shipping_cost, payment_method, payment_type, installments,
                        installment_amount, item_id, item_title, item_warranty, listing_type_id, category_id, unit_price, sale_fee, quantity, buyer_id, tags, fulfilled, pack_id, category_name, acess_token['usuario_id'],))
            cur.execute("UPDATE notification SET dados_retornados_api = %s, especificacao = %s WHERE notificacao = %s", (json.dumps(order_data), 'dados_novos',data_ant,))
        conn.commit()
        print("Dados do pedido inseridos ou atualizados com sucesso.")
    except Exception as e:
        print("Erro ao processar pedido:", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        # Garantir que conexão seja sempre fechada na ordem correta
        try:
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()
        except:
            pass
    #mensagem=1
    #prompt='com base nessa table:{table_colunas}, e essa mensagem:{mensagem}, retorne uma query que busque uma resposta para a mensagem, nao necessariamente essa seria uma busca unica'
    #cur.execute(query)
    #prompt com base nessas informaçoes essa mensagem consegue ser respondida completamente ou precisa de uma nova busca em outra table, retorne uma resposta se caso nao precisar, e retornae outra query se precisar =


def pos_venda_notifications(data,acess_token_data, data_ant):
    try:
        print("🔔 Notificação de pós-venda recebida:", data)
        resource_id = data.get('resource')
        access_token = acess_token_data['acess_token']  # ou busque do banco
        url = f"https://api.mercadolibre.com/messages/{resource_id}?tag=post_sale"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        m = response.json()
        id_ml = data.get('user_id')
        conn= get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT usuario_id FROM contas_mercado_livre WHERE id_ml=%s",(id_ml,))
        user_id_dict = cur.fetchone()
        user_id=user_id_dict['usuario_id']
        print('order_data:', m)
        cur.execute("UPDATE notification SET dados_retornados_api = %s WHERE notificacao = %s", (json.dumps(m),data_ant,))
        if isinstance(m.get('messages'), list):
            for i in m.get('messages'):
                message_resources = i.get('message_resources', [])
                for resource in message_resources:
                    if resource.get('name') == 'packs':
                        print("entrou no packs: ", resource)
                        pack_id= resource.get('id')
                        break
                print("pack_id:", pack_id)
                autor_comp = i.get('from').get('user_id')
                if autor_comp!=id_ml:
                    autor = 'cliente'
                    client_id = autor_comp
                else:
                    autor = 'vendedor'
                    client_id = i.get('to').get('user_id')
                cliente_nome = 'eu'
                mensagem = i.get('text')
                message_date = i.get('message_date', {})
                data_envio = message_date.get('created')
                tipo = 'post_sale'
                read= message_date.get('read')
                if read :
                    read = True
                message_moderation = i.get('message_moderation', {})
                status = message_moderation.get('status')
                is_first_message = i.get('conversation_first_message', False)
                cur.execute("SELECT message,item_id,date_created FROM messages WHERE usuario_id_messages=%s AND client_name=%s AND pack_id=%s",(user_id,cliente_nome,pack_id,))
                mensagem_existente = set()
                data_envio_existente = set()
                for row in cur.fetchall():
                    mensagem_existente.add(row['message'])
                    data_envio_existente.add(row['date_created'])
                if m.get('message_date') and data_envio_existente and mensagem_existente:
                    print("autor",autor)
                    mensagem=m.get('text')
                    if m.get('attachments'):
                        urls=[]
                        for atch in m.get('attachments'):
                            urls.append(atch.get('url'))
                    message_date=m.get('message_date')
                    data_envi=message_date['created']
    
                    if data_envi in data_envio_existente and mensagem in mensagem_existente:
                        print("Mensagem já existe no banco de dados, não inserindo novamente.")
                        conn.close()
                        cur.close()
                        return
            cur.execute('SELECT message,author FROM messages WHERE pack_id = %s',(pack_id,))
            mensagens_contexto = cur.fetchall() 
            if not mensagens_contexto :
              mensagens_contexto_com_usuario = 'nao existe'    
            else:
                mensagens_contexto_com_usuario=''
                for mensagem in mensagens_contexto:
                  mensagens_contexto_com_usuario += f"{mensagem['author']}: mensagem:{mensagem['message']}\n"
                print("data de envio:", data_envio)
                read_existe = message_date.get('read', False)
                read = True if read_existe else False
            cur.execute('INSERT INTO messages (usuario_id_messages,client_name,message,date_created,author,type,read,pack_id,is_first_message, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(user_id,cliente_nome,mensagem,data_envio,autor,tipo,read,pack_id,is_first_message, status))
            print("mensagem:", mensagem)
            print("data de envio:", data_envio)
            print("autor:", autor)
            print("cliente_nome:", cliente_nome)
            print("tipo:", tipo)
            print("is_first_message:", is_first_message)
            print("pack_id:", pack_id)
            print("read:", read)
    
            conn.commit()
            conn.close()
            cur.close()
        print("📩 Mensagem recebida:", mensagem)
    except Exception as e:
        print("Erro nas notificacao das mensagens pos-venda: ", str(e))
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()    

    # Por exemplo, salvar no banco de dados ou emitir um socket para o front-end
def pre_venda_notifications(data, acess_token_data):
    try:
        print("🔔 Notificação de pré-venda recebida:", data)
        resource_id = data.get('resource')
        access_token = acess_token_data['acess_token']  # ou busque do banco
        url=f"https://api.mercadolibre.com{resource_id}"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200 and response.status_code != 206:
            print("Erro ao acessar a API do Mercado Livre:", response.status_code, response.text)
            return jsonify({"error": "Erro ao acessar a API do Mercado Livre"}), response.status_code
        m = response.json()
        print("Pergunta recebida:", m)
        conn= get_db_connection()
        cur = conn.cursor()
        buyer_id = m.get('from',{}).get('id',None)
    
        client_name = buscar_nome(buyer_id, access_token) if buyer_id else {'nickname': None}
        print("Nome do cliente:", client_name['nickname'])
        item_id = m.get('item_id')
        status = m.get('status')
        text = m.get('text')
        date_created = m.get('date_created')
        print("buyer_id:", buyer_id)
        print("item_id:", item_id)
        print("status:", status)
        print("text:", text)
        print("date_created:", date_created)
        cur.execute("INSERT INTO messages (usuario_id_messages, client_name, message, date_created, author, type, status, item_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (acess_token_data['usuario_id'], client_name['nickname'],text, date_created, 'cliente' , 'pre_sale', status, item_id,))
        conn.commit()
        conn.close()
        cur.close()
        print("Pergunta processada com sucesso:")
    except Exception as e:
        print("Erro nas notificacao das mensagens pre-venda: ", str(e))
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def itens_notifications(data,acess_token_data):
    try:
        print("🔔 Notificação de itens recebida:", data)
        resource_id = data.get('resource')
        conn= get_db_connection()
        cur = conn.cursor()
        headers = {"Authorization": f"Bearer {acess_token_data['acess_token']}"}
        url = f"https://api.mercadolibre.com/{resource_id}"
        try:
            response = requests.get(url, headers=headers, timeout=15)
            # levanta exceção para qualquer código != 2xx
            response.raise_for_status()
        except requests.RequestException as e:
            print("Erro ao acessar a API do Mercado Livre:", e)
            # Aqui você pode atualizar a tabela notification marcando erro, se quiser.
            return {"ok": False, "error": f"Erro ML API: {e}"}
        item_data = response.json()
        item_id = item_data.get('id')
        nome_item = item_data.get('title')
        quantidade= item_data.get('available_quantity', 0)
        preco=item_data.get('price')
        status=item_data.get('status')
        print('pegando descrição')
        url_descricao = f"https://api.mercadolibre.com/items/{item_id}/description"
        response_descricao = requests.get(url_descricao, headers=headers)
        resposta_descricao = response_descricao.json()
        descricao = resposta_descricao.get('plain_text', 'Descrição não disponível')
        imagens = item_data.get('pictures', [])
        imagem = [img['url'] for img in imagens] if imagens else ['Sem imagem'] 
        preco_original = item_data.get('original_price', preco)
        preco_base = item_data.get('base_price', preco)
        disponivel = True
        tipo_ad = item_data.get('listing_type_id')
        category_id = item_data.get('category_id')
        url_cateogira=f'https://api.mercadolibre.com/categories/{category_id}'
        categoria_dados= requests.get(url_cateogira, headers=headers)
        categoria_json = categoria_dados.json()
        categoria = categoria_json.get('name', 'N/A')
        print("item_id:", item_id)
        print("nome_item:", nome_item)
        print("quantidade:", quantidade)
        print("preco:", preco)
        print("descricao:", descricao)
        print("imagem:", imagem)
        print("preco_original:", preco_original)
        print("preco_base:", preco_base)
        print("disponivel:", disponivel)
        print("tipo_ad:", tipo_ad)
        print("categoria:", categoria)
        cur.execute("SELECT * FROM itens WHERE item_id = %s", (item_id,))
        item_realdict = cur.fetchall()
        if item_realdict:
            print("Item já existe no banco de dados, atualizando item.")
            cur.execute("""
        UPDATE itens SET nome_item = %s, status = %s,quantidade = %s, preco = %s, descricao = %s, imagem = %s, preco_original = %s, preco_base = %s, disponivel = %s, tipo_ad = %s, categoria = %s
        WHERE item_id = %s AND usuario_id_item = %s             
    """,(nome_item, status,quantidade,preco,descricao,imagem,preco_original,preco_base,disponivel,tipo_ad,categoria,item_id,acess_token_data['usuario_id'],))
            print('Item atualizado com sucesso no banco de dados.')
            cur.execute("UPDATE notification SET dados_retornados_api = %s, especificacao = %s WHERE notificacao = %s", (json.dumps(item_data), 'item_existe',json.dumps(data),))
            pegar_anuncio_novo(item_id, acess_token_data['acess_token'], acess_token_data['usuario_id'],type='ja_possui')
        else :
            print("Item não existe no banco de dados, inserindo item.")
            cur.execute("""
                        INSERT INTO itens (item_id, nome_item, status,quantidade, preco, descricao, imagem, preco_original, preco_base, disponivel, tipo_ad, categoria, usuario_id_item) 
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,(item_id,nome_item, status,quantidade,preco,descricao,imagem,preco_original,preco_base,disponivel,tipo_ad,categoria,acess_token_data['usuario_id'],))
            print('Item inserido com sucesso no banco de dados.')
            pegar_anuncio_novo(item_id, acess_token_data['acess_token'], acess_token_data['usuario_id'],type='novo')
        conn.commit()
        cur.close()
        conn.close()
        return {"ok": True, "message": "Item processado com sucesso"}
    except Exception as e:
        print("Erro nas notificacao dos itens: ", str(e))
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# ================== CÓDIGO PARA RESPOSTAS AUTOMÁTICAS COM CHATGPT ==================

AUTHOR_CLIENT = "client"     # ajuste para "cliente" se for o caso
AUTHOR_SELLER = "seller"     # ajuste para "vendedor" se for o caso
MESSAGE_TYPE = "post_sale"   # filtramos só pós-venda

SYSTEM_PROMPT = (
    "Você é um atendente do(a) <LOJA>, cordial e objetivo, falando PT-BR.\n"
    "Regras:\n"
    "- Use somente os fatos do contexto; não invente prazos/políticas.\n"
    "- Se faltar dado, peça educadamente as informações necessárias.\n"
    "- 1–3 parágrafos curtos; emoji só se o cliente usar primeiro.\n"
)

# ====== UTIL: Anonimização simples (LGPD) ======
PHONE = re.compile(r'\b\+?\d{10,15}\b')
EMAIL = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

def anonymize(text: Optional[str]) -> str:
    s = text or ""
    s = PHONE.sub("<PHONE>", s)
    s = EMAIL.sub("<EMAIL>", s)
    return s.strip()

# ====== DB: BUSCA DAS MENSAGENS COM CONTEXTO ======
def fetch_messages_with_context(usuario_id: int) -> List[Dict[str, Any]]:
    """
    Retorna linhas ordenadas por conversa (pack_id) e tempo, com join em pedido e item.
    """
    sql = """
    SELECT
        m.pack_id,
        m.client_name,
        m.message,
        m.date_created,
        m.author,
        m.type,
        m.read,
        m.is_first_message,
        m.usuario_id_messages,
        m.item_id AS msg_item_id,

        -- Pedido relacionado ao pack
        p.id_order,
        p.status            AS pedido_status,
        p.date_created      AS pedido_date_created,
        p.last_updated      AS pedido_last_updated,
        p.paid_amount,
        p.total_amount,
        p.shipping_cost,
        p.quantity,
        p.nome_item         AS pedido_nome_item,
        p.item_id           AS pedido_item_id,
        p.category_name,
        p.pack_id           AS pedido_pack_id,

        -- Item detalhado (preferir item_id da mensagem; senão, do pedido)
        i.nome_item         AS item_nome,
        i.preco             AS item_preco,
        i.preco_original    AS item_preco_original,
        i.preco_base        AS item_preco_base,
        i.disponivel        AS item_disponivel,
        i.categoria         AS item_categoria,
        i.status            AS item_status
    FROM messages m
    LEFT JOIN pedidos_resumo p
           ON p.pack_id = m.pack_id
          AND p.usuario_id_pedidos_resumo = m.usuario_id_messages
    LEFT JOIN itens i
           ON i.item_id = COALESCE(m.item_id, p.item_id)
          AND i.usuario_id_item = m.usuario_id_messages
    WHERE m.usuario_id_messages = %s
      AND m.type = %s
    ORDER BY m.pack_id, m.date_created;
    """

    rows: List[Dict[str, Any]] = []
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (usuario_id, MESSAGE_TYPE))
        for r in cur.fetchall():
            rows.append(dict(r))
    return rows

def compact_context(row: Dict[str, Any]) -> str:
    blocos = []
    if row.get("id_order") or row.get("pedido_status"):
        linhas = []
        if row.get("id_order"): linhas.append(f"Pedido: {row['id_order']}")
        if row.get("pedido_status"): linhas.append(f"Status: {row['pedido_status']}")
        if row.get("paid_amount") is not None and row.get("total_amount") is not None:
            linhas.append(f"Pago/Total: {row['paid_amount']}/{row['total_amount']}")
        if row.get("shipping_cost") is not None:
            linhas.append(f"Frete: {row['shipping_cost']}")
        if row.get("quantity") is not None:
            linhas.append(f"Quantidade: {row['quantity']}")
        if linhas: blocos.append(" | ".join(linhas))
    if row.get("item_nome") or row.get("pedido_nome_item"):
        nome_item = row.get("item_nome") or row.get("pedido_nome_item")
        linhas = [f"Item: {nome_item}"]
        if row.get("item_preco") is not None: linhas.append(f"Preço atual: {row['item_preco']}")
        if row.get("item_preco_original") is not None: linhas.append(f"Preço original: {row['item_preco_original']}")
        if row.get("item_categoria"): linhas.append(f"Categoria: {row['item_categoria']}")
        blocos.append(" | ".join(linhas))
    return "\n".join(blocos) if blocos else "Sem contexto adicional."

def build_sft_examples(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Agrega blocos 1..N mensagens do cliente seguidas da PRIMEIRA resposta do vendedor.
    Cria 1 exemplo por pareamento, no formato de chat (messages[]).
    """
    by_pack: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_pack[r["pack_id"]].append(r)

    examples: List[Dict[str, Any]] = []
    for pack_id, msgs in by_pack.items():
        buffer_cliente: List[str] = []
        contexto_pack: Optional[str] = None

        for row in msgs:
            if contexto_pack is None:
                contexto_pack = compact_context(row)

            author = (row.get("author") or "").lower()
            if author == AUTHOR_CLIENT:
                buffer_cliente.append(anonymize(row.get("message")))
            elif author == AUTHOR_SELLER:
                if buffer_cliente:
                    user_content = (
                        f"[CONTEXT]\n{contexto_pack or 'Sem contexto adicional.'}\n\n"
                        f"[MENSAGEM_CLIENTE]\n" + "\n---\n".join(buffer_cliente)
                    )
                    assistant_content = anonymize(row.get("message"))
                    ex = {
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_content},
                            {"role": "assistant", "content": assistant_content},
                        ],
                        "metadata": {
                            "pack_id": pack_id,
                            "id_order": row.get("id_order"),
                            "msg_item_id": row.get("msg_item_id"),
                        }
                    }
                    examples.append(ex)
                    buffer_cliente = []
            else:
                pass
    return examples

def split_and_save_jsonl(examples: List[Dict[str, Any]], out_dir: str, seed: int = 42) -> Tuple[str, str, str]:
    import os
    os.makedirs(out_dir, exist_ok=True)
    random.Random(seed).shuffle(examples)

    packs = defaultdict(list)
    for ex in examples:
        packs[ex["metadata"]["pack_id"]].append(ex)
    pack_ids = list(packs.keys())
    random.Random(seed).shuffle(pack_ids)

    n = len(pack_ids)
    n_train = int(0.8 * n)
    n_val = int(0.1 * n)
    train_ids = set(pack_ids[:n_train])
    val_ids = set(pack_ids[n_train:n_train + n_val])

    splits = {"train": [], "val": [], "test": []}
    for pid, items in packs.items():
        if pid in train_ids: splits["train"].extend(items)
        elif pid in val_ids: splits["val"].extend(items)
        else: splits["test"].extend(items)

    paths = {}
    for split, data in splits.items():
        path = os.path.join(out_dir, f"{split}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for ex in data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
        paths[split] = path
    return paths["train"], paths["val"], paths["test"]

# ====== FINE-TUNING (OpenAI) ======
def _upload_jsonl_to_openai(client, path: str) -> str:
    """
    Faz upload do arquivo JSONL e retorna o file_id.
    Usa Files/Uploads API (qualquer uma serve para obter file_id).
    """
    # Opção A (Files API clássica)
    try:
        with open(path, "rb") as f:
            file_obj = client.files.create(file=f, purpose="fine-tune")
        return file_obj.id
    except Exception:
        # Opção B (Uploads API nova)
        up = client.uploads.create(
            purpose="fine-tune",
            file={"path": path}
        )
        # Espera o processamento de upload concluir e pegar o file_id final
        while up.status in ("pending", "processing"):
            time.sleep(2)
            up = client.uploads.retrieve(up.id)
        if up.status != "completed" or not up.file:
            raise RuntimeError(f"Falha no upload de {path}: status={up.status}")
        return up.file.id

def train_openai_finetune(
    data_dir: str,
    base_model: str = "gpt-4.1-mini",  # recomendado p/ custo/latência
    n_epochs: int = 2,
    suffix: Optional[str] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> str:
    """
    Cria um job de fine-tuning na OpenAI e retorna o nome do modelo fine-tunado.
    """
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    train_file_id = _upload_jsonl_to_openai(client, os.path.join(data_dir, "train.jsonl"))
    val_file_path = os.path.join(data_dir, "val.jsonl")
    val_file_id = _upload_jsonl_to_openai(client, val_file_path) if os.path.exists(val_file_path) else None

    # Hiperparâmetros simples (auto batching é comum). Campos suportados podem evoluir no tempo.
    hyper = {"n_epochs": n_epochs}

    job = client.fine_tuning.jobs.create(
        model=base_model,
        training_file=train_file_id,
        validation_file=val_file_id,
        hyperparameters=hyper,
        suffix=suffix or "novai-ft",
        metadata=metadata or {}
    )

    # Polling básico até concluir
    jid = job.id
    status = job.status
    while status in ("validating_files", "queued", "running"):
        time.sleep(10)
        job = client.fine_tuning.jobs.retrieve(jid)
        status = job.status

    if status != "succeeded":
        raise RuntimeError(f"Fine-tuning falhou: status={status}, job_id={jid}")

    ft_model = job.fine_tuned_model
    if not ft_model:
        raise RuntimeError("Job finalizado sem 'fine_tuned_model'.")
    return ft_model

# ====== TESTE DE GERAÇÃO (OpenAI) ======
def sample_random_item_and_order(usuario_id: int) -> Optional[Dict[str, Any]]:
    sql_item = """
    SELECT i.item_id, i.nome_item, i.categoria, i.preco, i.preco_original
    FROM itens i
    WHERE i.usuario_id_item = %s
    ORDER BY random()
    LIMIT 1;
    """
    sql_order = """
    SELECT p.id_order, p.pack_id, p.status, p.total_amount, p.paid_amount
    FROM pedidos_resumo p
    WHERE p.usuario_id_pedidos_resumo = %s
      AND p.item_id = %s
    ORDER BY random()
    LIMIT 1;
    """
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute(sql_item, (usuario_id,))
        item = cur.fetchone()
        if not item:
            return None
        item = dict(item)
        cur.execute(sql_order, (usuario_id, item["item_id"]))
        order = cur.fetchone()
        order = dict(order) if order else {}
    return {"item": item, "order": order}

def synth_customer_message(sample: Dict[str, Any]) -> str:
    nome_item = sample["item"].get("nome_item") or "<item>"
    id_order = sample["order"].get("id_order")
    templates = [
        f"Oi, tudo bem? Comprei o {nome_item} e ele chegou com um defeito. Como faço a troca? Pedido {id_order}.",
        f"Olá! Meu {nome_item} ainda não chegou. Consegue verificar o status, por favor? Pedido {id_order}.",
        f"Boa tarde! Recebi o {nome_item}, mas veio faltando uma peça. Como podemos resolver? Pedido {id_order}.",
        f"Oi, o {nome_item} está diferente do anúncio. Posso devolver? Pedido {id_order}."
    ]
    return random.choice(templates)

def build_context_from_sample(sample: Dict[str, Any]) -> str:
    blocos = []
    item = sample.get("item") or {}
    order = sample.get("order") or {}
    if order:
        linhas = [f"Pedido: {order.get('id_order')}", f"Status: {order.get('status')}"]
        if order.get("paid_amount") is not None and order.get("total_amount") is not None:
            linhas.append(f"Pago/Total: {order['paid_amount']}/{order['total_amount']}")
        blocos.append(" | ".join([s for s in linhas if s and s != "None"]))
    if item:
        linhas = [f"Item: {item.get('nome_item')}"]
        if item.get("preco") is not None: linhas.append(f"Preço atual: {item['preco']}")
        if item.get("preco_original") is not None: linhas.append(f"Preço original: {item['preco_original']}")
        if item.get("categoria"): linhas.append(f"Categoria: {item['categoria']}")
        blocos.append(" | ".join([s for s in linhas if s and s != "None"]))
    return "\n".join(blocos) if blocos else "Sem contexto adicional."

def test_model_generation_openai(
    usuario_id: int,
    model_id: str,  # pode ser o ft_model retornado acima
    temperature: float = 0.3,
    top_p: float = 0.9,
    max_tokens: int = 256
) -> Optional[str]:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    sample = sample_random_item_and_order(usuario_id)
    if not sample:
        print("[WARN] Não foi possível amostrar item/pedido para teste.")
        return None

    user_text = f"[CONTEXT]\n{build_context_from_sample(sample)}\n\n[MENSAGEM_CLIENTE]\n{synth_customer_message(sample)}"
    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_text},
    ]
    # Chat Completions com o modelo FT
    resp = client.chat.completions.create(
        model=model_id,
        messages=msgs,
        temperature=temperature,
        top_p=top_p,
        max_tokens=max_tokens
    )
    return (resp.choices[0].message.content or "").strip()

# ====== ORQUESTRADOR ======
def run_pipeline_openai(usuario_id: int, data_out_dir: str = "./data-ft", base_model: str = "gpt-4.1-mini"):
    rows = fetch_messages_with_context(usuario_id)
    if not rows:
        print("[ERRO] Nenhuma mensagem encontrada para este usuário.")
        return

    examples = build_sft_examples(rows)
    if not examples:
        print("[ERRO] Não foi possível formar pares cliente→vendedor.")
        return

    train_path, val_path, test_path = split_and_save_jsonl(examples, data_out_dir)
    print(f"[OK] Salvos:\n- {train_path}\n- {val_path}\n- {test_path}")

    # Cria o FT job (você pode usar um sufixo com o usuário, apenas como rótulo)
    ft_model = train_openai_finetune(
        data_dir=data_out_dir,
        base_model=base_model,
        n_epochs=2,
        suffix=f"novai-u{usuario_id}",
        metadata={"usuario_id": str(usuario_id), "projeto": "NOVAI"}
    )
    print(f"[OK] Modelo fine-tunado: {ft_model}")

    # Teste rápido
    resposta = test_model_generation_openai(usuario_id, model_id=ft_model)
    if resposta:
        print("\n=== RESPOSTA DO MODELO (teste sintético) ===\n")
        print(resposta)
    else:
        print("[WARN] Teste não executado (sem item/pedido amostrado).")


def pegar_anuncio_novo(item_id, acess_token,user_id,type):
    try:
        print("Pegando anuncio novo")
        conn = get_db_connection()
        cur = conn.cursor()
        advertiser_id='MLB'
        url = f"https://api.mercadolibre.com/advertising/product_ads/items/{item_id}"
        headers = {
            "Authorization": f"Bearer {acess_token}",
            'api-version': '2',
        }
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Erro ao buscar anúncios promovidos para o item {item_id}: {e}")
            return
        data = response.json()
        listingtype_id = data.get('listing_type_id', 'N/A')
        price = data.get('price', 0.0)
        title = data.get('title', 'N/A')
        campanha_id = data.get('campaign_id', None)
        status = data.get('status', 'N/A')
        has_discount = data.get('has_discount', False)
        catalog_listing = data.get('catalog_listing', False)
        condition = data.get('condition', 'N/A')
        logistic_type = data.get('logistic_type', 'N/A')
        domain_id = data.get('domain_id', 'N/A')
        date_created = data.get('date_created', 'N/A')
        buy_box_winner = data.get('buy_box_winner', False)
        channel = data.get('channel', 'N/A')
        brand_value_id = data.get('brand_value_id', 'N/A')
        brand_value_name = data.get('brand_value_name', 'N/A')
        thumbnail = data.get('thumbnail', 'N/A')
        current_level = data.get('current_level', 'N/A')
        diferred_stock = data.get('diferred_stock', False)
        permalink = data.get('permalink', 'N/A')
        recomended = data.get('recommended', False)
        image_quality = data.get('image_quality', 'N/A')
        ###Pegando dados da campanha_id:###
        final = datetime.now().date()
        inicio = final - timedelta(days=1)
        url = f'''https://api.mercadolibre.com/advertising/product_ads/campaigns/{campanha_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount,impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark'''
        response_campanha = requests.get(url, headers=headers)
        if response_campanha.status_code not in [200, 206]:
            return response_campanha.status_code
        result = response_campanha.json()
        name_campanha = result.get('name', 'N/A')
        status_campanha = result.get('status', 'N/A')
        strategy_campanha = result.get('strategy', 'N/A')
        budget_campanha = result.get('budget', 0.0)
        automatic_budget_campanha = result.get('automatic_budget', False)
        currency_id_campanha = result.get('currency_id', 'N/A')
        last_updated_campanha = result.get('last_updated', 'N/A')
        date_created_campanha = result.get('date_created', 'N/A')
        channel_campanha= result.get('channel', 'N/A')
        acos_target_campanha = result.get('acos_target', 0.0)
        if campanha_id:
            cur.execute('SELECT campanha_id FROM campanhas WHERE usuario_id_campanhas=%s AND campanha_id=%s', (user_id,campanha_id))
        dict= cur.fetchone()
        if dict:
            campanhas_id_exitentes=dict['campanha_id']
        else: campanhas_id_existentes=None
        if type=='novo':
            cur.execute('''
            INSERT INTO anuncios (id_anuncio ,item_id, listing_type_id, price, title, status, has_discount, catalog_listing, condition, logistic_type, domain_id, date_created, buy_box_winner, 
            channel, brand_value_id, brand_value_name, thumbnail, current_level, diferred_stock, permalink, recomended, image_quality, usuario_id_anuncios) VALUES 
            (%s ,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''', (item_id,item_id ,listingtype_id, price, title, status, has_discount, catalog_listing, condition, 
            logistic_type, domain_id, date_created, buy_box_winner, channel, brand_value_id, brand_value_name, thumbnail, current_level, diferred_stock, permalink, recomended, image_quality, user_id,))
            if not campanhas_id_existentes:
                cur.execute('INSERT INTO campanhas (campanha_id,nome,status,strategy,budget,currency_id,last_updated,date_created,channel,acos_target,usuario_id_campanhas) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (campanha_id) DO NOTHING',(campanha_id,name_campanha,status_campanha,strategy_campanha,budget_campanha,currency_id_campanha,last_updated_campanha,date_created_campanha,channel_campanha,acos_target_campanha,user_id,))
                conn.commit()
                cur.execute('UPDATE anuncios SET campanha_id = %s WHERE item_id = %s AND usuario_id_anuncios = %s', (campanha_id, item_id, user_id,))
            conn.commit()
        else:
            cur.execute('''
            UPDATE anuncios SET listing_type_id=%s, price=%s, title=%s, status=%s, has_discount=%s, catalog_listing=%s, condition=%s, logistic_type=%s, domain_id=%s, date_created=%s, buy_box_winner=%s, 
            channel=%s, brand_value_id=%s, brand_value_name=%s, thumbnail=%s, current_level=%s, diferred_stock=%s, permalink=%s, recomended=%s, image_quality=%s WHERE item_id=%s AND usuario_id_anuncios=%s
            ''',(listingtype_id, price, title, status, has_discount, catalog_listing, condition, 
            logistic_type, domain_id, date_created, buy_box_winner, channel, brand_value_id, brand_value_name, thumbnail, current_level, diferred_stock, permalink, recomended, image_quality,item_id, user_id,))
            if not campanhas_id_existentes:
                cur.execute('INSERT INTO campanhas (campanha_id,nome,status,strategy,budget,currency_id,last_updated,date_created,channel,acos_target,usuario_id_campanhas) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (campanha_id) DO NOTHING',(campanha_id,name_campanha,status_campanha,strategy_campanha,budget_campanha,currency_id_campanha,last_updated_campanha,date_created_campanha,channel_campanha,acos_target_campanha,user_id,))
                conn.commit()
                cur.execute('UPDATE anuncios SET campanha_id = %s WHERE item_id = %s AND usuario_id_anuncios = %s', (campanha_id, item_id, user_id,))
                conn.commit()
            else:
                cur.execute("""
                UPDATE campanhas
                SET nome = %s,status = %s,strategy = %s,budget = %s,currency_id = %s,last_updated = %s,
                    date_created = %s,channel = %s,acos_target = %s WHERE campanha_id = %s AND usuario_id_campanhas = %s
                """, (
                name,status,strategy,budget,currency_id,last_updated,date_created,channel,acos_target,campanha_id,user_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Erro ao pegar anúncio novo: {str(e)}")
        return {"ok": False, "error": str(e)}





# LOGIN, SISTEMA DE VERIFICAÇÃO DE CONTA
@app.route('/user-login', methods=['POST'])
def user_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    agora=datetime.now()
    print("agora:",agora)
    if not email or not password:
        return jsonify({"error": "Email e senha são obrigatórios"}), 400
    try:
        print("entrou no try")
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        print("entrou no banco de dados")
        # Busca o usuário pelo e-mail no banco
        cur.execute("SELECT * FROM usuarios WHERE email = %s;", (email,))
        user = cur.fetchone()
        print(user['id'])
        cur.execute("SELECT expiracao_token FROM contas_mercado_livre WHERE usuario_id=%s",(user['id'],))
        expiracao=cur.fetchone()
        print("Valor de expiracao:", expiracao)
        if user:
            if agora>expiracao["expiracao_token"]:
                print("verificou que o token expirou")
                cur.execute("SELECT refresh_token FROM contas_mercado_livre WHERE usuario_id=%s",(user['id'],))
                refresh=cur.fetchone()
                dados=renovar_access_token(refresh["refresh_token"])
                print("retornando os dados:", dados)
                access_token=dados["access_token"]
                print(access_token)
                refresh=dados["novo_refresh_token"]
                print(refresh)
                expiracao=dados["nova_expiracao"]
                print(expiracao)
                cur.execute("UPDATE contas_mercado_livre SET acess_token=%s,refresh_token=%s,expiracao_token=%s WHERE usuario_id=%s",(access_token,refresh,expiracao,user["id"]))
                conn.commit()
            hashed_password = user['senha']
            # Verifica se a senha fornecida bate com o hash armazenado
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['user_id'] = user['id'] # Salva o ID do usuário na sessão
                jwt_token=gerar_token(user['id'])
                #getApiMercadoLivre(jwt_token)
                cur.execute('SELECT status FROM first_sync WHERE usuario_id_first_sync = %s',(user['id'],))
                status_dict=cur.fetchone()
                if status_dict:
                    status = status_dict['status']
                else:
                    status='sync_nao_iniciada'
                print("retornando front end tudo ok")
                resp=jsonify({
                    "message": "Login bem-sucedido",
                    "status": status,
                    "user": {"id": user['id'], "email": user['email']},
                    "token": jwt_token  # Aqui você pode implementar a geração de um token real
                })
                resp.set_cookie(
                key=COOKIE_NAME,
                value=jwt_token,
                httponly=True,
                secure=True,
                samesite="None",
                path="/",          # obrigatório para __Host-
                # sem Domain -> host-only
                max_age=60*60*24,
            )
                cur.close()
                conn.close()
                return resp, 200
            else:
                print("retornando erro 1")
                return jsonify({"message": "Credenciais inválidas", "status": "error"}), 401
        else:
            print('retornando erro 2')
            return jsonify({"message": "Usuário não encontrado", "status": "error"}), 404


    except Exception as e:
        print("Erro capturado:", str(e))
        print("retornando erro 3")
        return jsonify({"error": str(e)}),500
    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()



#VERIFICAÇÃO DE USUARIO, VERIFICA SE O TOKEN GERADO ESTA ASSINADO OU NAO EXPIRADO
@app.route('/verificar_id', methods=['POST'])
def verificar_id():
    print("Entrou no verificar_id")
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Cabeçalho Authorization ausente"}), 401
    # Obtém o user_id dos parâmetros da query string
    token = auth_header.split(" ")[1] if " " in auth_header else auth_header
    print("Token:", token)
    try:
        decoded_token=decode_token(token)
        print(decoded_token)
        user_id=decoded_token.get("sub")
        print(user_id)
        exp_timestamp = decoded_token.get("exp")
        now = int(time.time())
        if exp_timestamp and exp_timestamp < now:
            return jsonify({"error": "Token expirado"}), 333
        if not user_id:
            return jsonify({"error": "Parâmetro user_id ausente"}), 400
        # Conecta ao banco de dados
        conn = get_db_connection()
        cur = conn.cursor()
        print("entrou o banco de dados")
        # Consulta o e-mail do usuário na tabela 'usuarios'
        cur.execute("SELECT email FROM usuarios WHERE id = %s;", (user_id,))
        user_data = cur.fetchone()
        if not user_data:
            print('usuario não encontrado')
            return jsonify({"error": "Usuário não encontrado"}), 404

        user_email = user_data['email']

        cur.execute("SELECT modo_automatico FROM usuarios WHERE id=%s",(user_id,))
        user_modo=cur.fetchone()
        modo_automatico=user_modo['modo_automatico']
        print("modo_automatico:", modo_automatico)
        # Consulta o token de acesso na tabela 'contas_mercado_livre'
        # (Note que usamos a coluna 'acess' conforme a sua criação)
        cur.execute(
            "SELECT acess_token FROM contas_mercado_livre WHERE usuario_id = %s ORDER BY id DESC LIMIT 1;",
            (user_id,)
        )
        token_row = cur.fetchone()
        if not token_row:
            print('Conta do Mercado Livre não encontrada para este usuário')
            return jsonify({"error": "Conta do Mercado Livre não encontrada para este usuário"}), 404

        access_token = token_row['acess_token']
        print(access_token)
        # Faz uma requisição para a API do Mercado Livre para pegar os dados do usuário
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        ml_response = requests.get("https://api.mercadolibre.com/users/me", headers=headers)
        if ml_response.status_code not in [200, 206]:
            print('Erro ao acessar a API do Mercado Livre')
            return jsonify({
                "error": "Erro ao acessar a API do Mercado Livre",
                "status_code": ml_response.status_code,
                "details": ml_response.text
            }), ml_response.status_code
        ml_user_data = ml_response.json()
        # Por exemplo, pegamos o 'nickname' como o nome da conta
        account_name = ml_user_data.get("nickname", "N/A")
        print(account_name)
        id_ml=ml_user_data["id"]
        print("id da conta do mercado livre",id_ml)     
        conn.commit()
        cur.execute("SELECT modo_automatico FROM usuarios WHERE id=%s",(user_id,))
        print("Saiu do verificar_id, user_id: ", user_id, 'user_email: ', user_email, 'account_name: ', account_name)
        return jsonify({"valid": True, "user_id": user_id, "user_email": user_email, "account_name": account_name, 'modo_automatico':modo_automatico,}), 200

    except Exception as e:
        print("Erro:", str(e))
        return jsonify({"error": str(e),"valid":False}), 500

    finally:
        # Certifique-se de fechar o cursor e a conexão
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()


###                         ###
###TODAS AS ROTAS SOCKET.ON ###
###                         ###

@socketio.on('connect')
def handle_connect():
    token = request.cookies.get('__Host-token')
    print('CONNECT host=', request.host)
    print('CONNECT cookies=', request.headers.get('Cookie'))
    if not token:
        print('conectado sem token')
    else:
        try:
            user_id = int(decode_token(token)['sub'])
            room=f'user:{user_id}'
            join_room(room)
            print('conectado')
        except Exception:
            return False  # rejeita a conexão se não autenticar 
      

@socketio.on('disconnect')
def handle_disconnect():
    print('usuario desconectado')


@socketio.on("getMensagens")
def getMensagens(payload):
    try:
        print("entrou no getMensagens")
        token=payload.get('token')
        tipo=payload.get("tipo")
        decoded_token=decode_token(token)
        user_id=payload.get('user_id', decoded_token.get('sub'))
        conn = get_db_connection()
        cur = conn.cursor()
        print("user_id:", user_id)
        print("tipo:", tipo)
        cur.execute("""
        SELECT cliente_nome, mensagem, data_envio, autor
        FROM mensagens_clientes
        WHERE usuario_id_mensagem = %s AND tipo = %s
        ORDER BY data_envio ASC
        """, (user_id, tipo))

        rows = cur.fetchall()

        cur.execute("SELECT DISTINCT ON (cliente_nome) cliente_nome,mensagem,data_envio,item_id,autor FROM mensagens_clientes WHERE usuario_id_mensagem=%s AND tipo=%s ORDER BY cliente_nome,data_envio DESC", (user_id,tipo))
        rows_clientes=cur.fetchall()



        # Converte cada row (RealDictRow) em dict puro e serializa o datetime
        mensagens = []
        for row in rows:
            mensagens.append({
                "cliente_nome": row["cliente_nome"],
                "mensagem":     row["mensagem"],
                "data_envio":   row["data_envio"].isoformat(),    # ou .strftime("%Y-%m-%d %H:%M:%S")
                "autor":         row["autor"],
            })
        clientes=[]
                # Supondo que 'cur' é seu cursor do banco de dados
        # Você pode adicionar um WHERE se souber quais item_ids são relevantes
        # ex: WHERE item_id IN (lista_de_item_ids_dos_seus_clientes)
        cur.execute("SELECT item_id, imagem FROM itens")
        todos_os_itens_com_imagem = cur.fetchall()
        mapa_imagens = {}
        if todos_os_itens_com_imagem: # Verifica se a lista não está vazia
            for item_db_row in todos_os_itens_com_imagem:
                # Acessando os valores usando as chaves do dicionário (RealDictRow)
                id_do_item = item_db_row['item_id']
                lista_urls_imagem = item_db_row['imagem'] # Isso é uma lista de URLs

                # Verifica se a lista de URLs não está vazia e pega a primeira URL
                if lista_urls_imagem and len(lista_urls_imagem) > 0:
                    url_imagem_principal = lista_urls_imagem[0] # Pega a primeira URL da lista
                    mapa_imagens[id_do_item] = url_imagem_principal
                else:
                    # Se a lista de imagens estiver vazia para este item_id,
                    # você pode armazenar None ou um placeholder.
                    mapa_imagens[id_do_item] = None
        else:
            print("A lista 'todos_os_itens_com_imagem' está vazia ou não foi carregada.")
        for cliente_info in rows_clientes: # 'cliente_info' é cada dicionário/objeto da sua lista original
            item_id_do_cliente = cliente_info['item_id'] # Ou como você acessa o item_id do cliente
            imagem_correspondente = mapa_imagens.get(item_id_do_cliente)
            clientes.append({
                "cliente_nome": cliente_info['cliente_nome'],
                "mensagem": cliente_info['mensagem'],
                "data_envio": cliente_info["data_envio"].isoformat(),
                "autor": cliente_info['autor'],
                "item_id": item_id_do_cliente,
                "imagem": imagem_correspondente # Adiciona a imagem encontrada ou None
            })
        data={
            "mensagens":mensagens,
            "clientes":clientes,
        }
        print("data:", data)
        cur.close() 
        conn.close()
        emit("respostaGetMensagens",data, broadcast=True)

    except Exception as e:
        print("Erro ao pegar os dados:", str(e))



@socketio.on('mudarModo')
def mudar_modo_automatico(modo):
    try:
        print("Entrou no mudarModo")
        modo_automatico=modo.get('modo', False)
        print("modo_automatico:", modo_automatico)
        token=modo.get('token', None)
        decoded_token=decode_token(token)
        user_id=decoded_token.get('sub')
        conn=get_db_connection()
        cur=conn.cursor()
        cur.execute("UPDATE usuarios SET modo_automatico=%s WHERE id=%s",(modo_automatico,user_id,))
        conn.commit()
        cur.execute("SELECT acess_token FROM contas_mercado_livre WHERE usuario_id=%s",(user_id,))
        token_access=cur.fetchone()
        access_token=token_access['acess_token']
        cur.execute("SELECT id_ml FROM contas_mercado_livre WHERE usuario_id=%s",(user_id,))
        seller=cur.fetchone()
        seller_id=seller['id_ml']
        cur.close()

        conn.close()
        print(access_token)

        run_pipeline_openai('1')

        #t = threading.Thread(target=listar_todos_itens, args=(user_id,seller_id,access_token))
        #t.start()
        #t = threading.Thread(target=faturamento_por_pedidos, args=(user_id,))
        #t.start()
        #t = threading.Thread(target=promocoes, args=(user_id, access_token,seller_id))
        #t.start()
        #t = threading.Thread(target=listar_conversas_pos_venda, args=(user_id,seller_id,access_token))
        #t.start()
        #t = threading.Thread(target=reclamacoes, args=(access_token,user_id))
        #t.start()
        #t = threading.Thread(target=faturamento, args=(user_id,))
        #t.start()
        #t = threading.Thread(target=listar_conversas_pre_venda, args=(user_id,seller_id,access_token))
        #t.start()
        #t = threading.Thread(target=dados_vendedor, args=(access_token,user_id))
        #t.start()
        #t = threading.Thread(target=campanhas_e_anuncios, args=(user_id,access_token))
        #t.start()
        #chat('Conforme imagem do carregador e logo vou testar com o multímetro as baterias.','Lava Jato Portátil Alta Pressão Recarregável 2 Bateria Carro','Descrição: ATENÇÃO: Para o primeiro uso, conecte diretamente à torneira para remover o ar da máquina. Após isso, utilize normalmente no balde. Antes de usar o produto, carregue por 12 horas para uma carga completa. Transforme a limpeza em uma tarefa simples e sem esforço com a nossa Lavadora Jato Portátil de Alta Pressão, agora disponível para você! Seja em casa, no jardim, no carro ou em qualquer lugar que precise de uma limpeza poderosa, esta lavadora portátil é sua melhor aliada. Características Principais: -Alta Pressão Onde Você Precisa: Ajuste a intensidade conforme a necessidade da limpeza, de sujeiras leves a resistentes. -Portátil e Recarregável: Equipada com duas baterias recarregáveis para total liberdade de movimento. -Acessórios Completos: Bico extensor, dispenser de sabão, mangueira e mais para uma limpeza eficaz. -Fácil de Transportar e Armazenar: Guardada em uma maleta resistente e prática. -Ecológica e Econômica: Utilize apenas a quantidade necessária de água, evitando desperdícios. Conteúdo do Pacote: 1 Lavadora Jato Portátil de Alta Pressão 1 Filtro 2 Bicos (Alta Pressão/Spray) 1 Bico Extensor 1 Dispenser de Sabão 1 Mangueira 1 Fonte de Carregamento 2 Baterias 1 Maleta Resistente Ficha Técnica: -Consumo: 4L por minuto -Tensão do Carregador: 110V/220V (bivolt) -Bateria: 48v -Tempo de Recarga: 2-3 horas -Tempo de Uso: 1-3 horas -Funcionalidades: 3 -Bocal de Alta Pressão -Níveis de Pressão: Alto, Médio, Baixo - Com níveis de Pressão: Desde lavar carros até regar plantas. Material: Plástico com circuitos elétricos CUIDADOS: Quanto tempo dura a bateria? R: Até 1 hora. Esse modelo vem com os acessórios? R: Sim, com todos os descritos na descrição do produto. Qual é a pressão da máquina? R: 870 Psi de pressão. Pode usar com a mangueira em um balde com água? R: Sim, pode ser usada conectada à torneira ou em um balde com água. A carga dela é bivolt? R: Sim, o carregador pode ser usado em 110V ou 220V. A bateria vem junto e qual a amperagem dela? R: Sim, vem com a bateria de 4000mAh. Tensão do carregador: 110V/220V, 50Hz/60Hz. Vocês têm bateria separada? R: Sim temos, só solicitar o link ou ir em "Ver mais anúncios do vendedor" Não utilize sem água. Mantenha longe do alcance de crianças e animais. Evite contato com o corpo quando utilizada com altas pressões. Não desmonte o produto. Verifique o encaixe correto da bateria. Evite quedas do produto. Certifique-se de que o produto está devidamente carregado antes de usar.','Boa noite, recebi o produto, porém nao esta certo, na descricao diz que ele e de 48 volts, mas oque veio na verdade e de 21 volts',)
        #chat_novai_manager_separador_de_pergunta('quais produtos eu vendo melhor?',user_id)

    except Exception as e:
        print("Erro no mudarmodo:", str(e))

@socketio.on('getItens')
def getItens(data):
    try:
        token=data.get('token')
        decoded_token=decode_token(token)
        user_id=decoded_token.get('sub')
        conn=get_db_connection()
        cur=conn.cursor()
        cur.execute('SELECT item_id,nome_item,quantidade,preco,descricao,imagem,preco_original,preco_base FROM itens WHERE usuario_id_item=%s',(user_id,))
        row_itens=cur.fetchall()

        itens_detalhes=[]
        for row in row_itens:
            itens_detalhes.append({
                'item_id':row['item_id'],
                'nome_item':row['nome_item'],
                "quantidade":row['quantidade'],
                'preco':row['preco'],
                'descricao':row['descricao'],
                'imagem':row['imagem'],
                'preco_original':row['preco_original'],
                'preco_base':row['preco_base'],
            })
        for i,row in enumerate(row_itens[0]):
            print(f'{i}: printou= {type(row)}')
        emit('RespostaGetItens', { 'itens': itens_detalhes })
    except Exception as e:
        print("Erro em getItens:", str(e))
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass
@socketio.on("mensagem_cliente")
def mensagem_cliente(data):
    try:
        token = data.get('token')
        print("Token:", token)
        decoded_token=decode_token(token)
        print(decoded_token)
        user_id=decoded_token.get("sub")
        print("user_id:", user_id)
        cliente_nome = data["cliente_nome"]
        mensagem     = data["mensagem"]
        autor        = data["autor"]
        item=data['item_id']
        data_envio   = datetime.now()
        tipo=data['tipo']
        print("mensagem enviada:", mensagem)
        print("cliente_nome:", cliente_nome)
        print("autor:", autor)
        print("item:", item)
        print("data_envio:", data_envio)
        print("tipo:", tipo)
        # 1) salva no banco
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT modo_automatico FROM usuarios WHERE id=%s",(user_id,))
        modo_row=cur.fetchone()
        modo=modo_row['modo_automatico'] if modo_row else False
        print("modo:", modo)
        cur.execute(
            "INSERT INTO mensagens_clientes (usuario_id_mensagem, cliente_nome, mensagem, data_envio, autor,tipo,item_id) VALUES (%s, %s, %s, %s,%s,%s,%s)",
            (user_id, cliente_nome, mensagem, data_envio, autor,tipo,item)
        )
        print("Mensagem salva no banco de dados")
        cur.execute("SELECT nome_item,descricao FROM itens WHERE item_id=%s",(item,))
        item_data = cur.fetchone()
        nome_item = item_data.get('nome_item','Item não encontrado')
        detalhes = item_data.get('descricao','Descrição não encontrada')
        conn.commit()
        cur.close()
        conn.close()

        # 2) Se veio do cliente, chama a OpenAI e emite a resposta
        if autor == "cliente":
            if modo:
                resposta = chat_pos_venda(mensagem,nome_item,detalhes)  # devolve só a string
                autor_resposta='vendedor'
            print("resposta do chat:",resposta)
            # opcional: também salvar no banco a resposta do assistente
            conn = get_db_connection()
            cur  = conn.cursor()
            cur.execute(
                "INSERT INTO mensagens_clientes (usuario_id_mensagem, cliente_nome, mensagem, data_envio, autor,tipo,item_id) VALUES (%s, %s, %s, %s, %s,%s,%s)",
                (user_id, cliente_nome, str(resposta), datetime.now(), autor_resposta,tipo,item)
            )
            conn.commit()
            cur.close()
            conn.close()
            payload={
                "user_id":user_id,
                "token":token,
                "tipo":tipo,
            }
            print("payload:", payload)
            # agora emite pro front-end
        # 3) Por fim, atualiza a lista completa de mensagens (se for esse seu fluxo)

        getMensagens(payload)

    except Exception as e:
        print("erro ao armazenar mensagem:", str(e))


def sync_lock_acquire(user_id: int) -> bool:
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s) AS got", (int(user_id),))
        row = cur.fetchone()
        return bool(row["got"])

def sync_lock_release(user_id: int):
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s) AS done", (int(user_id),))

###                         ###
### FUNÇÕES A SEREM CHAMADAS###
###                         ###

@socketio.on('verificar_status')
def verificar_status():
    try: 
        token = request.cookies.get("__Host-token")
        print('token verificar_status', token)
        if not token:
            print('sem token')
            return {'status': 'Sem Token'}
        decoded = decode_token(token)
        user_id = int(decoded.get('sub'))
        print('user_id', user_id)
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM usuarios WHERE id=%s", (user_id,))
            if cur.fetchone():
                print('Encontrou o usuario')
                cur.execute("SELECT status FROM first_sync WHERE usuario_id_first_sync= %s", (user_id,))
                status_dict=cur.fetchone()
                if status_dict:
                    print('usuario com status')
                    status = status_dict['status']
                    room=f'user:{user_id}'
                    socketio.emit('status_loading',{'message':'Aguarde mais alguns minutos,\n esse processo pode demorar um pouco...'},room=room)
                    return {'status':status,'token':token}
                else:
                    print('usuario sem status, Inserindo status')
                    cur.execute('INSERT INTO first_sync (status,usuario_id_first_sync) VALUES (%s,%s)',('sync_em_processamento',user_id,))
                    conn.commit()
                    return {'status': 'sync_nao_iniciada','token':token}
            else:
                return {'status':'Sem Token'}
    except Exception as e:
        print('erro ao verificar_status: ', e)

@socketio.on('pegar_dados_iniciais')
def pegar_dados_gerais():
    try:
        print('pegar_dados_geraisF')
        token = request.cookies.get("__Host-token")
    
        if not token:
            return False
        print('token', token)
        try:
            decoded = decode_token(token)
            user_id = int(decoded.get('sub'))
        except jwt.InvalidTokenError:
            return False
        room=f'user:{user_id}'
        print('token depois:', token)
        emit('guardar_token', {'token':token}, room=room)
        socketio.sleep(3)   
        socketio.start_background_task(run_pipeline, user_id, room)
        emit('status_loading', {'message': 'Iniciando sincronização...'}, room=room)
    except Exception as e:
        print(f'erro: {str(e)}')
        return False
        
def run_pipeline(user_id, room):
    try:
        # garante exclusividade por usuário
        if not sync_lock_acquire(user_id):
            socketio.emit('status_loading',
                          {'message': 'Já existe sincronização em andamento.', 'status': False},
                          room=room)
            return

        # pegue tudo o que precisa em UMA consulta
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT acess_token, id_ml
                FROM contas_mercado_livre
                WHERE usuario_id = %s
            """, (user_id,))
            row = cur.fetchone()

        if not row:
            socketio.emit('status_loading',
                          {'message': 'Conta não encontrada.', 'status': False},
                          room=room)
            return

        access_token = row['acess_token']
        seller_id    = row['id_ml']
        # etapas com yields para cooperar com eventlet
        socketio.emit('status_loading', {'message': 'Pegando itens do vendedor...'}, room=room)
        listar_todos_itens(user_id, seller_id, access_token)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Analisando anúncios e campanhas...'}, room=room)
        campanhas_e_anuncios(user_id, access_token,room)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Sincronizando dados do vendedor...'}, room=room)
        dados_vendedor(access_token, user_id)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Armazenando pedidos...'}, room=room)
        faturamento_por_pedidos(user_id,room)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Mensagens pós-venda...'}, room=room)
        listar_conversas_pos_venda(user_id, seller_id, access_token,room)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Perguntas pré-venda...'}, room=room)
        listar_conversas_pre_venda(user_id, seller_id, access_token)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Reclamações...'}, room=room)
        reclamacoes(access_token, user_id, room)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Promoções...'}, room=room)
        promocoes(user_id, access_token, seller_id)
        socketio.sleep(0)

        socketio.emit('status_loading', {'message': 'Concluído!','status':True}, room=room)
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute('UPDATE first_sync SET status = %s WHERE usuario_id_first_sync =%s', ('concluido',user_id,))
            conn.commit()

    except Exception as e:
        socketio.emit('status_loading',
                      {'message': f'Erro: {e}', 'status': False},
                      room=room)
    finally:
        sync_lock_release(user_id)



def buscar_item(item_id,access_token):
    url=f"https://api.mercadolibre.com/items/{item_id}"

    headers={
        "Authorization":f"Bearer {access_token}"
    }
    response=requests.get(url,headers=headers)
    return response.json()

def listar_conversas_pos_venda(user_id, seller_id, access_token,room):
    try:
        print("Entrou na função listar_conversas_pos_venda")
        conn = get_db_connection()
        cur = conn.cursor()
    
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        url = 'https://api.mercadolibre.com/messages/unread?tag=post_sale'
        resp = requests.get(url, headers=headers)
        resposta = resp.json()
        results = resposta.get('results',[])
        count_20 = 0
        change = 0
        for result in results:
            resource = result.get('resource', None)
            pack_id = resource.split('/')[2]
            print('pack id', pack_id)
    
            url = f"https://api.mercadolibre.com/messages/{resource}?mark_as_read=false&tag=post_sale"
            response = requests.get(url, headers=headers)
            data = response.json()
            paging = data.get('paging')
            total = paging.get('total')
            total_int = int(total)
            if total>0 and isinstance(data,dict):
                messages = data.get('messages')
        
                if messages and isinstance(messages, list):
                    for message in messages:
                        if isinstance(message,dict) and message.get('text'):
                            from_user = message.get('from', {}).get('user_id')
                            to_user = message.get('to', {}).get('user_id')
                            author = 'buyer' if from_user != seller_id else 'seller'
                            client_id = from_user if author == 'buyer' else to_user
                            client_name = buscar_nome(client_id, access_token)
        
                            is_first_message = message.get('conversation_first_message', False)
                            text = message.get('text')
                            created_at = message.get('message_date', {}).get('created')
                            read_flag = message.get('message_date', {}).get('read') is not None
                            if text and created_at:
                                created_at_brazil = converter_zona_pro_brasil(created_at)
                                cur.execute('INSERT INTO packs (pack_id,usuario_id_packs) VALUES (%s,%s) ON CONFLICT (pack_id) DO NOTHING ',(int(pack_id),user_id,))
                                conn.commit()
                                cur.execute('''
                                    INSERT INTO messages (
                                        client_name, message, date_created, author,
                                        type, read, pack_id, is_first_message,usuario_id_messages
                                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                ''', (
                                    client_name['nickname'],
                                    text,
                                    created_at_brazil,
                                    author,
                                    'post_sale',
                                    read_flag,
                                    int(pack_id),
                                    is_first_message,
                                    user_id,
                                )) 
                            conn.commit()
            count_20 +=1
            if count_20>20:
                if change == 1:
                    change = 0
                    message = 'Buscando menssagens pós-venda'
                else:
                    change = 1
                    message = 'Isso pode demorar um pouco'
                socketio.emit('status_loading', {'message':message},room=room)                    
                count_20 = 0
                socketio.sleep(1)
                
        cur.close()
        conn.close()
    except Exception as e:
        print(f'erro: {str(e)}')
    print('Terminou de pegar as mensagens pos-venda')



def reclamacoes(access_token, user_id, room):
    try:
        print("Entrou na função de reclamações")
        change=0
        count_20=0
        base_url = "https://api.mercadolibre.com"
        headers = {"Authorization": f"Bearer {access_token}"}
        offset = 0
        limit = 30
        conn = get_db_connection()
        cur = conn.cursor()
    
        while True:
            url = f"https://api.mercadolibre.com/post-purchase/v1/claims/search?status=opened&offset={offset}&limit={limit}"
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                break
    
    
            data_geral = response.json()
            data = data_geral.get("data", [])
    
            if not data:
                break
    
            for claim in data:
                claim_id = claim.get("id")
                resource = claim.get("resource")
                resource_id = claim.get('resource_id')
                if resource=='order':
                    order_id=resource_id
                    cur.execute("SELECT pack_id FROM pedidos_resumo WHERE id_order=%s",(order_id,))
                    pack_id_dict = cur.fetchone()
                    pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
                elif resource == 'shipment':
                    shipment_id = claim.get('resource_id') 
                    
                    url_order_shipment = f"https://api.mercadolibre.com/shipments/{shipment_id}/items"
                    response_order_shipment = requests.get(url_order_shipment, headers=headers)
                    
                    pack_id = None # Garante que pack_id seja definido
                    
                    if response_order_shipment.status_code in [200, 206]:
                        order_items = response_order_shipment.json()
                        
                        # VERIFICA SE A RESPOSTA É UMA LISTA E NÃO ESTÁ VAZIA
                        if isinstance(order_items, list) and order_items:
                            # Pega o order_id do PRIMEIRO item da lista
                            order_id = order_items[0].get("order_id")
                            
                            if order_id:
                                cur.execute("SELECT pack_id FROM pedidos_resumo WHERE id_order=%s", (order_id,))
                                pack_id_dict = cur.fetchone()
                                pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
                else :
                     pack_id= None
    
    
                status = claim.get("status")
                tipo = claim.get("type")
                stage = claim.get("stage")
                parent_id = claim.get("parent_id")  
                reason_id = claim.get("reason_id")
                fulfilled = claim.get("fulfilled")
                quantity_type = claim.get("quantity_type")
                site_id = claim.get("site_id")
                date_created = claim.get("date_created")
                last_updated = claim.get("last_updated")
    
                # Players
                comprador_id = None
                vendedor_id = None
                acoes_disponiveis = []
    
                players = claim.get("players", [])
                for player in players:
                    if player["role"] == "complainant" and player["type"] == "buyer":
                        comprador_id = player["user_id"]
                    if player["role"] == "respondent" and player["type"] == "seller":
                        vendedor_id = player["user_id"]
                        acoes_disponiveis = [acao["action"] for acao in player.get("available_actions", [])]
                url_reason = f"{base_url}/post-purchase/v1/claims/reasons/{reason_id}"
                response_reason = requests.get(url_reason, headers=headers)
                if response_reason.status_code != 200:
                    reason = None
                else:
                    reason_data = response_reason.json()
                    #print(f'reason_data: {reason_data}')
                    nome_reason = reason_data.get("name")
                    #print(f"Nome da razão: {nome_reason}")
                    settings = reason_data.get("settings", {})
                    expected_solution = settings.get('expected_resolutions', [])
    
                #print('--------------------------------')
                url_details = f"{base_url}/post-purchase/v1/claims/{claim_id}/detail"
                response_details = requests.get(url_details, headers=headers)
                if response_details.status_code in [200, 206]:
                    details = response_details.json()
                    #print(f'Details: {details}')
                    title = details.get("title")
                    due_date_detail = details.get("due_date")
                    description = details.get("description")
                    action_responsible = details.get("action_responsible")
                    problem= details.get("problem")
    
                 #Inserir no banco
    
                cur.execute('''
                    INSERT INTO reclamacoes (
                        claim_id, resource_id, status, tipo, stage, parent_id, pack_id, reason_id,
                      fulfilled, quantity_type, site_id, date_created, last_updated,
                        comprador_id, vendedor_id, acoes_disponiveis,name_reason,expected_solutions,problem,description,due_date,title,action_responsible,usuario_id_reclamacoes,resource
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (claim_id) DO NOTHING
                ''', (
                   claim_id, resource_id, 'open', tipo, stage, parent_id, pack_id, reason_id,
                   fulfilled, quantity_type, site_id, date_created, last_updated,
                 comprador_id, vendedor_id, acoes_disponiveis,nome_reason,expected_solution,problem, description, due_date_detail,title,action_responsible,user_id,resource
                ))
                conn.commit()
            count_20+=1
            if count_20>20:
                if change==1:
                    change=0
                    message='Buscando reclamacoes'
                else:
                    change = 1
                    message = 'Isso pode demorar alguns minutos'
                count_20=0
                socketio.emit('status_loading', {'message':message}, room=room)
                socketio.sleep(1)
            conn.commit()
            offset += limit
            time.sleep(0.2)
            #request para claims fechadas
        offset = 0
        count_20=0
        while True:
            url = f"https://api.mercadolibre.com/post-purchase/v1/claims/search?status=closed&offset={offset}&limit={limit}"
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                break
            data_geral = response.json()
            data = data_geral.get("data", [])
            if not data or offset>300:
                break
            for i,claim in enumerate(data):
                claim_id = claim.get("id")
                resource = claim.get("resource")
                resource_id = claim.get("resource_id")
                if resource=='order':
                    order_id=resource_id
                    cur.execute("SELECT pack_id from pedidos_resumo WHERE id_order=%s",(order_id,))
                    pack_id_dict = cur.fetchone()
                    pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
                elif resource == 'shipment':
                    # No primeiro loop, o resource_id estava faltando, já corrigido aqui:
                    shipment_id = claim.get('resource_id') 
                    
                    url_order_shipment = f"https://api.mercadolibre.com/shipments/{shipment_id}/items"
                    response_order_shipment = requests.get(url_order_shipment, headers=headers)
                    
                    pack_id = None # Garante que pack_id seja definido
                    
                    if response_order_shipment.status_code in [200, 206]:
                        order_items = response_order_shipment.json()
                        
                        # VERIFICA SE A RESPOSTA É UMA LISTA E NÃO ESTÁ VAZIA
                        if isinstance(order_items, list) and order_items:
                            # Pega o order_id do PRIMEIRO item da lista
                            order_id = order_items[0].get("order_id")
                            
                            if order_id:
                                cur.execute("SELECT pack_id FROM pedidos_resumo WHERE id_order=%s", (order_id,))
                                pack_id_dict = cur.fetchone()
                                pack_id = pack_id_dict['pack_id'] if pack_id_dict else None
                else :
                     pack_id= None
                status = claim.get("status")
                tipo = claim.get("type")
                stage = claim.get("stage")
                parent_id = claim.get("parent_id")
                reason_id = claim.get("reason_id")
                fulfilled = claim.get("fulfilled")
                quantity_type = claim.get("quantity_type")
                site_id = claim.get("site_id")
                date_created = claim.get("date_created")
                last_updated = claim.get("last_updated")
                resolution = claim.get("resolution", {})
                # Players
                comprador_id = None
                vendedor_id = None
                acoes_disponiveis = []
    
                players = claim.get("players", [])
                for player in players:
                    if player["role"] == "complainant" and player["type"] == "buyer":
                        comprador_id = player["user_id"]
                    if player["role"] == "respondent" and player["type"] == "seller":
                        vendedor_id = player["user_id"]
                        acoes_disponiveis = [acao["action"] for acao in player.get("available_actions", [])]
    
                reason = None
                resolution_date_created = None
                benefited = []
                closed_by = None
                apllied_coverage = False
    
                if resolution:
                    reason = resolution.get("reason")
                    resolution_date_created = resolution.get("date_created")
                    benefited = resolution.get("benefited")
                    closed_by = resolution.get("closed_by")
                    apllied_coverage = resolution.get("applied_coverage", False)
    
                url_reason = f"{base_url}/post-purchase/v1/claims/reasons/{reason_id}"
                response_reason = requests.get(url_reason, headers=headers)
                if response_reason.status_code != 200:
                    reason = None
                else:
                    reason_data = response_reason.json()
                    #print(f'reason_data: {reason_data}')
                    nome_reason = reason_data.get("name")
    
                #print('--------------------------------')
    
    
    
                url_details = f"{base_url}/post-purchase/v1/claims/{claim_id}/detail"
                response_details = requests.get(url_details, headers=headers)
    
                if response_details.status_code != 200:
                    title = None
                    due_date_detail = None
                    description = None
                    action_responsible = None
                    problem= None
                else:
                    details = response_details.json()
                    #print(f'Details: {details}')
                    title = details.get("title")
                    description = details.get("description")
    
    
    
                # Inserir no banco
                cur.execute('''
                    INSERT INTO reclamacoes (
                        claim_id, resource_id, status, tipo, stage, parent_id, pack_id, reason_id,
                        fulfilled, quantity_type, site_id, date_created, last_updated,
                        comprador_id, vendedor_id, acoes_disponiveis,name_reason, description, title,reason_resolution,
                        date_resolution, benefited, resolution_closed_by, apllied_coverage ,usuario_id_reclamacoes,resource
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (claim_id) DO NOTHING
                ''', (
                    claim_id, resource_id, status, tipo, stage, parent_id, pack_id, reason_id,
                    fulfilled, quantity_type, site_id, date_created, last_updated,
                    comprador_id, vendedor_id, acoes_disponiveis,nome_reason,description,title,reason,resolution_date_created,benefited,closed_by,apllied_coverage,user_id,resource
                ))
            count_20+=1
            if count_20>20:
                if change==1:
                    change=0
                    message='Buscando reclamacoes'
                else:
                    change = 1
                    message = 'Isso pode demorar alguns minutos'
                count_20=0
                socketio.emit('status_loading', {'message':message}, room=room)
            time.sleep(0.2)
            offset += limit
            conn.commit()
        
    except Exception as e:
        print(f'erro: {str(e)}')
    print('Terminou de pegar as reclamacoes')


    print("✅ Sincronização de reclamações finalizada com sucesso.")


@app.route('/promotions-and-items', methods=['GET'])
def get_promotions_and_items():
    print('entrou no promotions-and-items')
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Cabeçalho Authorization ausente"}), 401

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header

    try:
        decoded_token = decode_token(token)
    except ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as exc:
        return jsonify({"error": f"Falha ao decodificar token: {exc}"}), 400

    user_id = decoded_token.get("sub") if decoded_token else None
    print(user_id)
    if not user_id:
        return jsonify({"error": "Usuário não encontrado no token"}), 400
    query = """
        SELECT 
            p.id_promotion,
            p.name,
            p.status,
            p.start_date,
            p.finish_date,
            p.deadline_date,
            p.type_promotion,
            i.item_id,
            i.nome_item,
            i.imagem[1] AS image_url,  -- Pegando a primeira imagem do array
            pim.price,
            pim.original_price,
            pim.min_discounted_price,
            pim.max_discounted_price,
            pim.suggested_discounted_price,
            pim.start_date AS item_start_date,
            pim.end_date AS item_end_date,
            pim.auto AS item_auto
        FROM 
            promotion p
        JOIN 
            ponte_item_promotions pim ON p.id_promotion = pim.id_promotion
        JOIN 
            itens i ON pim.item_id = i.item_id
        WHERE
            p.usuario_id_promotions = %s  
        ORDER BY 
            p.start_date DESC;
    """
    
    try:
    # Conexão ao banco de dados e execução da consulta
        with get_db_connection() as conn, conn.cursor() as cur:
            # Substitua %s pelo ID do usuário autenticado
            cur.execute(query, (user_id,))
            results = cur.fetchall()
    
            # Processando os resultados para o formato esperado
            promotions_list = []
            items_list = []
            processed_promotions = set()
            for row in results:
                if row['id_promotion'] not in processed_promotions:
                    promotion = {
                        'id_promotion': row['id_promotion'],
                        'name': row['name'] if row['name'] else 'N/A',  # Atribuir valor padrão caso esteja None
                        'status': row['status'],
                        'start_date': row['start_date'].strftime('%Y-%m-%dT%H:%M:%SZ') if row['start_date'] else 'N/A',
                        'finish_date': row['finish_date'].strftime('%Y-%m-%dT%H:%M:%SZ') if row['finish_date'] else 'N/A',
                        'deadline_date': row['deadline_date'].strftime('%Y-%m-%dT%H:%M:%SZ') if row['deadline_date'] else 'N/A',
                        'type_promotion': row['type_promotion'],
                    }
                    promotions_list.append(promotion)
                    processed_promotions.add(row['id_promotion'])
                item = {
                    'item_id': row['item_id'],
                    'promotion_name': row['name'],
                    'nome_item': row['nome_item'],
                    'image_url': row['image_url'] if row['image_url'] else '',  # Garantir que a imagem seja uma string vazia se não houver imagem
                    'price': float(row['price']) if row['price'] else 0.0,  # Garantir que o preço seja 0 caso esteja None
                    'original_price': float(row['original_price']),
                    'min_discounted_price': float(row['min_discounted_price']) if row['min_discounted_price'] else 0.0,
                    'max_discounted_price': float(row['max_discounted_price']) if row['max_discounted_price'] else 0.0,
                    'suggested_discounted_price': float(row['suggested_discounted_price']) if row['suggested_discounted_price'] else 0.0,
                    'start_date': row['item_start_date'].strftime('%Y-%m-%dT%H:%M:%SZ') if row['item_start_date'] else 'N/A',
                    'end_date': row['item_end_date'].strftime('%Y-%m-%dT%H:%M:%SZ') if row['item_end_date'] else 'N/A',
                    'renovacao_auto':row['item_auto'],
                }
                items_list.append(item)
    
                # Adiciona a promoção com seus itens
        
        # Retorna os dados no formato JSON
        return jsonify({
        'promotions': promotions_list,
        'itemsAppliedToPromotions': items_list,
    })

    except Exception as e:
        return jsonify({'error': str(e)}), 500



def faturamento_por_pedidos(user_id, room):
    print("entrou no faturamento_por_pedidos")
    try:
        conn=get_db_connection()
        cur=conn.cursor()
        cur.execute("SELECT acess_token,id_ml FROM contas_mercado_livre WHERE usuario_id = %s", (user_id,))
        token_acess=cur.fetchone()
        access_token=token_acess['acess_token']
        id=token_acess['id_ml']

        url_pages=f"https://api.mercadolibre.com/orders/search?seller={id}"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url_pages, headers=headers)
        resposta=response.json()
        paging=resposta.get('paging')
        total_pages=paging.get('total')
        count_20 = 0
        change = 0
        for offset in range(0,total_pages,50):
            url = f"https://api.mercadolibre.com/orders/search?seller={id}&offset={offset}&limit=50&sort=date_desc"


            response = requests.get(url, headers=headers)
            if response.status_code not in [200, 206]:
                return []
            orders = response.json()
            results = orders.get("results", [])

            for result in results:
                payments = result.get("payments", [])
                row_payments = payments[0] if payments else {}
                id_order = row_payments.get('order_id')
                status = row_payments.get('status')
                paid_amount = row_payments.get('total_paid_amount', 0)
                installment = row_payments.get('installments', 0)
                installment_amount = row_payments.get('installment_amount', 0)        
                date_approved_z = row_payments.get('date_approved', 'Sem data')
                date_approved = converter_zona_pro_brasil(date_approved_z)
                payment_type = row_payments.get('payment_type', 'Sem tipo de pagamento')
                available_actions = row_payments.get('available_actions', [])
                coupon_id = row_payments.get('coupon_id', 'Sem cupom')
                coupon_amount = row_payments.get('coupon_amount', 0)
                taxes_amount = row_payments.get('taxes_amount', 0)
                shipping_cost = row_payments.get('shipping_cost', 0)
                overpaid_amount = row_payments.get('overpaid_amount', 0)
                payment_method_id = row_payments.get('payment_method_id', 'Sem método de pagamento')
                #print(f"id_payment = {id_payment}, id_order = {id_order}, status = {status}, transaction_amount = {transaction_amount}")
                #print(f"total_paid_amount = {total_paid_amount}, installment = {installment}, installment_amount = {installment_amount}")
                #print(f"date_created = {date_created}, date_approved = {date_approved}, date_last_modified = {date_last_modified}")
                #print(f"payment_type = {payment_type}, authorization_code = {autorization_code}, marketplace_fee = {marketplace_fee}")
                #print(f"available_actions = {available_actions}, coupon_id = {coupon_id}, coupon_amount = {coupon_amount}, taxes_amount = {taxes_amount}")
                #print(f"shipping_cost = {shipping_cost}, overpaid_amount = {overpaid_amount}, payment_method_id = {payment_method_id}")
                order_items = result.get('order_items', [])
                row_order_items = order_items[0] if order_items else {}
                item = row_order_items.get('item', [])
                item_title = item.get('title', 'Sem título')
                quantity = row_order_items.get('quantity', 0)   
                unit_price = row_order_items.get('unit_price', 0)
                full_unit_price = row_order_items.get('full_unit_price', 0)
                sale_fee = row_order_items.get('sale_fee', 0)
                warranty = item.get('warranty', 'Sem garantia')
                condition = item.get('condition', 'Sem condição')
                item_id = item.get('id')
                cur.execute("SELECT item_id FROM itens WHERE item_id = %s AND usuario_id_item = %s",(item_id, user_id,))
                if not cur.fetchone():
                    cur.execute('INSERT INTO itens (item_id,nome_item,usuario_id_item) VALUES (%s,%s,%s) ON CONFLICT (item_id) DO NOTHING',(item_id,item_title,user_id,))
                    conn.commit()
                listing_type_id = row_order_items.get('listing_type_id', 'Sem tipo de listagem')
                #print(f"item_title = {item_title}, quantity = {quantity}, unit_price = {unit_price}")
                #print(f"full_unit_price = {full_unit_price}, sale_fee = {sale_fee}, warranty = {warranty}")
                #print(f"condition = {condition}, item_id = {item_id}")


                fulfilled = result.get('fulfilled', False)

                date_created_order_z = result.get('date_created', 'Sem data de criação')
                date_created_order=converter_zona_pro_brasil(date_created_order_z)
                date_created_order_dt=datetime.fromisoformat(date_created_order).astimezone(timezone.utc)
                days_90=datetime.now(timezone.utc) - timedelta(days=90)
                if date_created_order_dt < days_90:
                    print('Passou dos 3 meses')
                    return
                date_closed_z = result.get('date_closed', 'Sem data de fechamento')
                date_closed=converter_zona_pro_brasil(date_closed_z)
                date_last_updated_order_z = result.get('date_last_updated', 'Sem data de atualização')
                date_last_updated_order=converter_zona_pro_brasil(date_last_updated_z)
                total_amount = result.get('total_amount', 0)
                paid_amount = result.get('paid_amount', 0)
                pack_id = result.get('pack_id', None)
                if not pack_id:
                   pack_id = id_order
                cur.execute("INSERT INTO packs (pack_id,usuario_id_packs) VALUES (%s,%s) ON CONFLICT (pack_id) DO NOTHING", (pack_id,user_id,))
                conn.commit()
                if item.get('category_id'):
                    url_categoria=f"https://api.mercadolibre.com/categories/{item.get('category_id')}"
                    response= requests.get(url_categoria, headers=headers)
                    if response.status_code in [200, 206]:
                        categoria_data = response.json()
                        category_id = categoria_data.get('id', 'Sem categoria')
                        category_name = categoria_data.get('name', 'Sem nome de categoria')
                else:
                    category_id = 'Sem categoria'
                    category_name = 'Sem nome de categoria'
                #print(f"fulfilled = {fulfilled}")
                #print(f"date_created_order = {date_created_order}, date_closed = {date_closed}, date_last_updated_order = {date_last_updated_order}")
                #print(f"total_amount = {total_amount}, paid_amount = {paid_amount}")
                try:
                    cur.execute('''INSERT INTO pedidos_resumo (id_order, date_created, date_closed, date_approved, last_updated, status, total_amount, paid_amount, shipping_cost, payment_method,
                                 payment_type, installments, installment_amount, item_id, nome_item, item_warranty, listing_type_id, category_name, unit_price, sale_fee, quantity, buyer_id, tags, 
                                fulfilled, pack_id, usuario_id_pedidos_resumo) VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id_order) DO NOTHING''',(id_order, date_created_order, date_closed, date_approved, date_last_updated_order, status,
                                 total_amount, paid_amount, shipping_cost, payment_method_id, payment_type, installment, installment_amount,
                                 item_id, item_title, warranty, listing_type_id, category_name, unit_price, sale_fee, quantity, result.get('buyer', {}).get('id', 'Sem comprador'),
                                    result.get('tags', []), fulfilled, pack_id, user_id,))
                    conn.commit()

                except Exception as e:
                    print(f"Erro ao inserir pedido {id_order}: {e}")

            count_20 += 1
            if count_20>20:
                if change == 0:
                    change = 1
                    message = 'isso pode demorar um pouco'
                else:
                    change = 0
                    message = 'Buscando Pedidos...'
                socketio.emit('status_loading', {'message':message}, room = room)
                socketio.sleep(1)
                count_20 = 0

        conn.close()
        #print('faturamento dos ultimos 50 pedidos: R$ ', faturamentos)

    except Exception as e:
        print("Erro no faturamento_ por pedidos:", str(e))
    print('Terminou de pegar os pedidos')
    
def faturamento(user_id):
    try:
        print('🔍 Entrou na função faturamento para o usuário:', user_id)

        # 🔌 Conexão e token
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT acess_token FROM contas_mercado_livre WHERE usuario_id = %s', (user_id,))
        token_access = cur.fetchone()
        access_token = token_access['acess_token']
        headers = {"Authorization": f"Bearer {access_token}"}

        # 🔄 Buscar todos os períodos disponíveis
        url_periodos = "https://api.mercadolibre.com/billing/integration/monthly/periods?group=ML&document_type=BILL&limit=12"
        response = requests.get(url_periodos, headers=headers)
        periodos_data = response.json()
        print(periodos_data)
        if 'results' not in periodos_data:
            print("❌ Nenhum período encontrado.")
            return

        # 📊 Iterar sobre os períodos
        for periodo in periodos_data['results']:
            key = periodo['key']  # Ex: "2024-12-01"
            print(f"\n📅 Período: {key}")

            # 🔧 ADICIONADO group=ML
            url_summary = f"https://api.mercadolibre.com/billing/integration/periods/key/{key}/summary/details?group=ML&document_type=BILL"


            response_summary = requests.get(url_summary, headers=headers)
            print("causa do erro: ", response_summary.text)

            if response_summary.status_code in [200, 206]:
                resumo = response_summary.json()
                if resumo:
                    resumo_period = resumo.get('period', '')
                    if resumo_period:
                        date_from = converter_zona_pro_brasil(resumo_period.get('date_from', 'Sem data'))
                        date_to = converter_zona_pro_brasil(resumo_period.get('date_to', 'Sem data'))
                        date_expiration = converter_zona_pro_brasil(resumo_period.get('expiration_date', 'Sem data de expiração'))
                        if resumo_period.get('debt_expiration_date'):
                            debt_expiration_date=converter_zona_pro_brasil(resumo_period.get('debt_expiration_date'))
                        else :
                            debt_expiration_date = None
                        period_status=resumo.get('period_status','')
                        print('Data de referencia: ', key)
                        print('📅 Data inicial do período:', date_from)
                        print('📅 Data final do período:', date_to)
                        print('📆 Data de expiração da fatura:', date_expiration)
                        print('data limite para pendencias de pagamento: ', debt_expiration_date)
                        print('status do periodo: ', period_status)
                    resumo_bill_includes = resumo.get('bill_includes', '')
                    if resumo_bill_includes:
                        print(resumo_bill_includes)
                        total_amount = resumo_bill_includes.get('total_amount', 'Sem total')
                        total_perception = resumo_bill_includes.get('total_perception', 'Sem total perception')
                        print('💰 Valor total faturado (total_amount):', total_amount)
                        print('📑 Total de percepções fiscais (total_perceptions):', total_perception)
                        #dentro de payment_collected#
                        payment_collected = resumo.get('payment_collected', {})
                        desconto_operacional = payment_collected.get('operation_discount', 'Sem desconto operacional')
                        total_payment = payment_collected.get('total_payment', 'Sem pagamento total')
                        total_credit_note = payment_collected.get('total_credit_note', 'Sem nota de crédito')
                        total_collected = payment_collected.get('total_collected', 'Sem total coletado')
                        total_debt = payment_collected.get('total_debt', 'Sem dívida restante')
                        print('🔻 Descontos operacionais (operation_discount):', resumo['payment_collected']['operation_discount'])
                        print('💵 Pagamento realizado (total_payment):', resumo['payment_collected']['total_payment'])
                        print('🧾 Notas de crédito recebidas (total_credit_note):', resumo['payment_collected']['total_credit_note'])
                        print('✅ Valor total efetivamente coletado (total_collected):', resumo['payment_collected']['total_collected'])
                        print('❗ Dívida restante (total_debt):', resumo['payment_collected']['total_debt'])
                        cur.execute('INSERT INTO faturas (key,date_from,date_to,date_expiration,debt_expiration_date,period_status,total_faturado,total_perception,descontos_operacionais,pagamento_realizado,total_credit_note,total_collected,total_debt) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(key,date_from,date_to,date_expiration,debt_expiration_date,period_status,total_amount,total_perception,desconto_operacional,total_payment,total_credit_note,total_collected,total_debt))
                        conn.commit()  
            else:
                print(f"⚠️ Erro ao obter resumo do período {key}: {response_summary.status_code}")

        cur.close()
        conn.close()
    except Exception as e:
        print('erro ao pegar faturamento :', e)



def listar_novas_conversas():
    print("Entrou na função listar_novas_conversas")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT usuario_id, acess_token FROM contas_mercado_livre")
    contas = cur.fetchall()
    for conta in contas:
        user_id = conta['usuario_id']
        access_token = conta['acess_token']
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        ml_response = requests.get("https://api.mercadolibre.com/users/me", headers=headers)
        response_ml=ml_response.json()
        id_ml=response_ml['id']
        print(f"Processando conta ID: {id}, User ID: {user_id}")
        try:
            listar_conversas_pre_venda(user_id,id_ml,access_token)
        except Exception as e:
            print(f"Erro ao listar conversas pré-venda para a conta ID {id}: {e}")
    cur.close()
    conn.close()

def dados_vendedor(access_token,user_id):
    try:
        print("Entrou na função dados_vendedor")
        url= "https://api.mercadolibre.com/users/me"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(url, headers=headers)
        if response.status_code not in [200, 206]:
            return {}
        dados = response.json()
        #dados sensíveis do vendedor#
        id_ml = dados.get('id')
        first_name = dados.get('first_name', 'N/A')
        last_name = dados.get('last_name', 'N/A')
        email = dados.get('email', 'N/A')
        indentification= dados.get('identification', {})
        identification_number = indentification.get('number', 'N/A')
        identification_type = indentification.get('type', 'N/A')
        address_data = dados.get('address', {})
        state= address_data.get('state', 'N/A')
        city = address_data.get('city', 'N/A')
        address = address_data.get('address', 'N/A')
        zip_code = address_data.get('zip_code', 'N/A')
        phone_data = dados.get('phone', {})
        area_code = phone_data.get('area_code', 'N/A')
        phone_number = phone_data.get('number', 'N/A')
        verified=phone_data.get('verified', False)
        conn = get_db_connection()
        cur=conn.cursor()
    
        #reputação do vendedor#
        seller_reputation = dados.get('seller_reputation', {})
        level_id = seller_reputation.get('level_id', 'N/A')
        power_seller_status = seller_reputation.get('power_seller_status', 'N/A')
        transactions = seller_reputation.get('transactions', {})
        period = transactions.get('period', 'N/A')
        total=transactions.get('total', 0)
        completed = transactions.get('completed', 0)
        canceled = transactions.get('canceled', 0)
        ratings = transactions.get('ratings', {})
        positive = ratings.get('positive', 0)
        neutral = ratings.get('neutral', 0)
        negative = ratings.get('negative', 0)
        tags= dados.get('tags', [])
        seller_experience = dados.get('seller_experience', 'N/A')
        #status da conta  e permições#
        status= dados.get('status', '{}')
        site_status = status.get('site_status', 'N/A')
    
        #informações extras do vendedor#
        nickname = dados.get('nickname', 'N/A')
        registration_date = dados.get('registration_date', 'N/A')
        site_id = dados.get('site_id', 'N/A')
        permalink = dados.get('permalink', 'N/A')
        shipping_modes = dados.get('shipping_modes', [])
        logo= dados.get('logo', 'N/A')
        points=dados.get('points', 0)
        credit= dados.get('credit', {})
        consumed_credit = credit.get('consumed', 0)
        credit_level_id = credit.get('credit_level_id', 0)
        user_type = dados.get('user_type', 'N/A')
        cur.execute('''INSERT INTO dados_vendedor (id_ml, first_name, last_name, email, identification_number, identification_type, state,
        city, address, zip_code, phone_number, verified, nickname, registration_date, site_id, permalink,shipping_modes, logo, usuario_id_dados_vendedor) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s,%s,%s,%s,%s)''',
        (id_ml, first_name, last_name, email, identification_number, identification_type, state, city, address, zip_code, phone_number, verified,nickname, registration_date,site_id, permalink, shipping_modes, logo, user_id,)) 
    
        cur.execute('''INSERT INTO reputacao_vendedor (level_id, power_seller_status, period, total_transactions, completed_transactions, canceled_transactions, positive_reviews, neutral_reviews, negative_reviews, tags, seller_experience,credit_level_id, consumed_credit, user_type, usuario_id_reputacao_vendedor) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s)''',
        (level_id, power_seller_status, period, total, completed, canceled, positive, neutral, negative,tags, seller_experience,credit_level_id, consumed_credit, user_type, user_id,))
    
        cur.execute('UPDATE contas_mercado_livre SET site_status = %s WHERE usuario_id = %s', (site_status, user_id,))
        conn.commit()
    
        cur.close()
        conn.close()
    except Exception as e:
        print(f'erro: {str(e)}')
    print('Terminou de pegar os dados do venedor')


def campanhas_e_anuncios(user_id, access_token,room):
    try:
        # Buscar anuncios
        count_20=0
        change=0
        print("Buscando anúncios do vendedor...")
        conn= get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT item_id FROM itens")
        itens = cur.fetchall()
        cont_certos = 0
        cont_errados = 0
        headers_url = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
        }
        campanhas = []
        item_ids = []
        advertising_id='MLB'
        for i,item in enumerate(itens):
            item_id = item['item_id']
            try:
                url = f"https://api.mercadolibre.com/advertising/product_ads/items/{item_id}"
                response = requests.get(url, headers=headers_url)
            except requests.exceptions.RequestException as e:
                cont_errados += 1
                continue

            if response.status_code not in [200, 206]:
                continue
            cont_certos +=1
            data = response.json()
            listingtype_id = data.get('listing_type_id', 'N/A')
            price = data.get('price', 0.0)
            title = data.get('title', 'N/A')
            campanha_id = data.get('campaign_id', 'N/A')
            status = data.get('status', 'N/A')
            has_discount = data.get('has_discount', False)
            catalog_listing = data.get('catalog_listing', False)
            condition = data.get('condition', 'N/A')
            logistic_type = data.get('logistic_type', 'N/A')
            domain_id = data.get('domain_id', 'N/A')
            date_created = data.get('date_created', 'N/A')
            buy_box_winner = data.get('buy_box_winner', False)
            channel = data.get('channel', 'N/A')
            brand_value_id = data.get('brand_value_id', 'N/A')
            brand_value_name = data.get('brand_value_name', 'N/A')
            thumbnail = data.get('thumbnail', 'N/A')
            current_level = data.get('current_level', 'N/A')
            diferred_stock = data.get('diferred_stock', False)
            permalink = data.get('permalink', 'N/A')
            recomended = data.get('recommended', False)
            image_quality = data.get('image_quality', 'N/A')


            cur.execute('''
            INSERT INTO anuncios (id_anuncio ,item_id, listing_type_id, price, title, status, has_discount, catalog_listing, condition, logistic_type, domain_id, date_created, buy_box_winner, 
            channel, brand_value_id, brand_value_name, thumbnail, current_level, diferred_stock, permalink, recomended, image_quality, usuario_id_anuncios) VALUES 
            (%s ,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id_anuncio) DO NOTHING''', (item_id,item_id ,listingtype_id, price, title, status, has_discount, catalog_listing, condition, 
            logistic_type, domain_id, date_created, buy_box_winner, channel, brand_value_id, brand_value_name, thumbnail, current_level, diferred_stock, permalink, recomended, image_quality, user_id,))
            if not status == 'idle' and not campanha_id == 'N/A' and not campanha_id == 0 and (campanha_id not in campanhas):
                campanhas.append(campanha_id)
                item_ids.append(item_id)

            inicio = datetime.now() - timedelta(days=90)

            final = datetime.now() - timedelta(days=1)



            url = f"https://api.mercadolibre.com/advertising/product_ads/items/{item_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount&aggregation_type=DAILY"
            response_summary = requests.get(url, headers=headers_url)
            if response_summary.status_code not in [200, 206]:
                return response_summary.status_code
            resumo_data = response_summary.json()

            results_resumo = resumo_data.get('results', [])
            for resumo in results_resumo:
                clicks = resumo.get('clicks', 0)
                prints = resumo.get('prints', 0)
                cost = resumo.get('cost', 0.0)
                cpc = resumo.get('cpc', 0.0)
                direct_amount = resumo.get('direct_amount', 0.0)
                indirect_amount = resumo.get('indirect_amount', 0.0)
                total_amount = resumo.get('total_amount', 0.0)
                direct_units_quantity = resumo.get('direct_units_quantity', 0)
                indirect_units_quantity = resumo.get('indirect_units_quantity', 0)
                units_quantity = resumo.get('units_quantity', 0)
                direct_items_quantity = resumo.get('direct_items_quantity', 0)
                indirect_items_quantity = resumo.get('indirect_items_quantity', 0)
                advertising_items_quantity = resumo.get('advertising_items_quantity', 0)
                organic_units_quantity = resumo.get('organic_units_quantity', 0)
                organic_items_quantity = resumo.get('organic_items_quantity', 0)
                acos = resumo.get('acos', 0.0)
                organic_units_amount = resumo.get('organic_units_amount', 0.0)
                sov = resumo.get('sov', 0.0)
                ctr = resumo.get('ctr', 0.0)
                cvr = resumo.get('cvr', 0.0)
                roas = resumo.get('roas', 0.0)
                date = resumo.get('date', 'N/A')    


                cur.execute('''
                INSERT INTO anuncios_metricas_diarias (id_anuncio, item_id, clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, 
                indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos,
                organic_amount,sov, ctr, cvr, roas, date,title, usuario_id_anuncios_metricas_diarias) VALUES (%s,%s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s,%s, %s, %s,%s, %s, %s, %s, %s,%s, %s, %s, %s, %s)
                ''', (
                item_id, item_id, clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity,
                indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos, organic_units_amount,sov, ctr, cvr, roas, date, title, user_id,))
            conn.commit()


            headers_url = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
            }
            #campanhas ativas do vendedor#

            count_20+=1
            if count_20>20:
                if change==1:
                    change=0
                    message='Buscando anuncios e campanhas'
                else:
                    change = 1
                    message = 'Isso pode demorar alguns minutos'
                count_20=0
                socketio.emit('status_loading', {'message':message}, room=room)
        conn.commit()
        cur.execute("""DELETE FROM anuncios_metricas_diarias
                    WHERE id_anuncio IN (
                    SELECT id_anuncio
                    FROM anuncios_metricas_diarias
                    WHERE date >= NOW() - INTERVAL '90 days' AND usuario_id_anuncios_metricas_diarias = %s
                    GROUP BY id_anuncio
                    HAVING MAX(clicks) < 1
                    )
                    AND date >= NOW() - INTERVAL '90 days';
                    """, (user_id,))
        for i,campanha_id in enumerate(campanhas):

            item_id = item_ids[i]

            if campanha_id == 'N/A' or campanha_id == 0 or not campanha_id:
                    continue

            url = f'''https://api.mercadolibre.com/advertising/product_ads/campaigns/{campanha_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount,impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark'''
            response_campanha = requests.get(url, headers=headers_url)
            if response_campanha.status_code not in [200, 206]:
                return response_campanha.status_code
            result = response_campanha.json()



            name = result.get('name', 'N/A')
            status = result.get('status', 'N/A')
            strategy = result.get('strategy', 'N/A')
            budget = result.get('budget', 0.0)
            automatic_budget = result.get('automatic_budget', False)
            currency_id = result.get('currency_id', 'N/A')
            last_updated = result.get('last_updated', 'N/A')
            date_created = result.get('date_created', 'N/A')
            channel= result.get('channel', 'N/A')
            acos_target = result.get('acos_target', 0.0)
            cur.execute('INSERT INTO campanhas (campanha_id,nome,status,strategy,budget,currency_id,last_updated,date_created,channel,acos_target,usuario_id_campanhas) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (campanha_id) DO NOTHING',(campanha_id,name,status,strategy,budget,currency_id,last_updated,date_created,channel,acos_target,user_id,))
            conn.commit()
            cur.execute('UPDATE anuncios SET campanha_id = %s WHERE item_id = %s AND usuario_id_anuncios = %s', (campanha_id, item_id, user_id,))
            conn.commit()
            #metricas diarias por campanha
            if status == 'active':
                url_campanhas_diaria = f"""https://api.mercadolibre.com/advertising/product_ads/campaigns/{campanha_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount,impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark&aggregation_type=DAILY"""
                response_campanhas_diaria = requests.get(url_campanhas_diaria, headers=headers_url)
                if response_campanhas_diaria.status_code not in [200, 206]:
                    return response_campanhas_diaria.status_code
                campanhas_diaria_data = response_campanhas_diaria.json() 
                results_diaria = campanhas_diaria_data.get('results', [])
                for result_diaria in results_diaria:
                    clicks = result_diaria.get('clicks', 0)
                    prints = result_diaria.get('prints', 0)
                    cost = result_diaria.get('cost', 0.0)
                    cpc = result_diaria.get('cpc', 0.0)
                    ctr = result_diaria.get('ctr', 0.0)
                    direct_amount = result_diaria.get('direct_amount', 0.0)
                    indirect_amount = result_diaria.get('indirect_amount', 0.0)
                    total_amount = result_diaria.get('total_amount', 0.0)
                    direct_units_quantity = result_diaria.get('direct_units_quantity', 0)
                    indirect_units_quantity = result_diaria.get('indirect_units_quantity', 0)
                    units_quantity = result_diaria.get('units_quantity', 0)
                    direct_items_quantity = result_diaria.get('direct_items_quantity', 0)
                    indirect_items_quantity = result_diaria.get('indirect_items_quantity', 0)
                    advertising_items_quantity = result_diaria.get('advertising_items_quantity', 0)
                    organic_units_quantity = result_diaria.get('organic_units_quantity', 0)
                    organic_units_amount = result_diaria.get('organic_units_amount', 0.0)
                    organic_items_quantity = result_diaria.get('organic_items_quantity', 0)
                    acos = result_diaria.get('acos', 0.0)
                    cvr = result_diaria.get('cvr', 0.0)
                    roas = result_diaria.get('roas', 0.0)
                    sov = result_diaria.get('sov', 0.0)
                    impression_share = result_diaria.get('impression_share', 0.0)
                    top_impression_share = result_diaria.get('top_impression_share', 0.0)
                    lost_impression_share_by_budget = result_diaria.get('lost_impression_share_by_budget', 0.0)
                    lost_impression_share_by_ad_rank = result_diaria.get('lost_impression_share_by_ad_rank', 0.0)
                    acos_benchmark = result_diaria.get('acos_benchmark', 0.0)
                    date = result_diaria.get('date', 'N/A')



                    cur.execute('''
                    INSERT INTO campanhas_metricas_diarias (campanha_id, clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,
                    total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,
                    organic_units_quantity, organic_amount, organic_items_quantity, acos,cvr, roas, sov, impression_share, top_impression_share,
                    lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark,nome, date, usuario_id_campanhas_metricas_diarias)
                    VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s,%s)''', (
                    campanha_id, clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,
                    direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_units_amount, organic_items_quantity, acos,
                    cvr, roas, sov, impression_share, top_impression_share,lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark, name,date, user_id,))

            count_20+=1
            if count_20>20:
                if change==1:
                    change=0
                    message='Buscando campanhas'
                else:
                    change = 1
                    message = 'Isso pode demorar alguns minutos'
                count_20=0
                socketio.emit('status_loading', {'message':message}, room=room)
        cur.execute("""DELETE FROM campanhas_metricas_diarias
                    WHERE campanha_id IN (
                    SELECT campanha_id
                    FROM campanhas_metricas_diarias
                    WHERE date >= NOW() - INTERVAL '90 days' AND usuario_id_campanhas_metricas_diarias = %s
                    GROUP BY campanha_id
                    HAVING MAX(clicks) < 1
                    )
                    AND date >= NOW() - INTERVAL '90 days';
                    """, (user_id,))
        conn.commit()
        conn.close()
        cur.close()

    except Exception as e:
        print(f"Erro ao buscar campanhas e anúncios: {e}")
    print('Terminou de pegar as campanhas e anuncios')

def campanhas_e_anuncios_periodico():
    print("Entrou na função campanhas_e_anuncios_periodico")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT usuario_id, acess_token, id_ml,expiracao_token FROM contas_mercado_livre")
    contas_data_dict = cur.fetchall()
    agora=datetime.now()
    for conta in contas_data_dict:
        expiracao_token = conta['expiracao_token']
        id_ml = conta['id_ml']
        if agora>expiracao_token:
            print("Token expirado, renovando...")
            print("verificou que o token expirou")
            cur.execute("SELECT refresh_token FROM contas_mercado_livre WHERE id_ml=%s",(id_ml,))
            refresh=cur.fetchone()
            dados=renovar_access_token(refresh["refresh_token"])
            print("retornando os dados:", dados)
            access_token=dados["access_token"]
            print(access_token)
            refresh=dados["novo_refresh_token"]
            print(refresh)
            expiracao=dados["nova_expiracao"]
            print(expiracao)
            cur.execute("UPDATE contas_mercado_livre SET acess_token=%s,refresh_token=%s,expiracao_token=%s WHERE id_ml=%s",(access_token,refresh,expiracao,id_ml,))
            conn.commit()
        else:
            access_token = conta['acess_token']
        usuario_id = conta['usuario_id']
        headers = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
        }
        cur.execute("SELECT item_id, nome_item FROM itens WHERE usuario_id_item = %s", (usuario_id,))
        itens_dict = cur.fetchall()
        ontem = agora - timedelta(days=1)
        for item in itens_dict:
            item_id = item['item_id']
            title = item['nome_item']
            print(f"Processando item_id: {item_id}")
            antes_de_ontem = agora - timedelta(days=2)
            print("ontem:", ontem)
            url = f"""https://api.mercadolibre.com/advertising/product_ads/items/{item_id}?date_from={ontem.strftime('%Y-%m-%d')}&date_to={ontem.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount&aggregation_type=DAILY"""
            response = requests.get(url,headers = headers)
            if response.status_code!=200 and response.status_code!=206:
                print('erro na chamada da api', response.text)
                continue
            resp = response.json()
            results_resumo=resp.get('results', [])
            for resumo in results_resumo:
                clicks = resumo.get('clicks', 0)
                prints = resumo.get('prints', 0)
                cost = resumo.get('cost', 0.0)
                cpc = resumo.get('cpc', 0.0)
                direct_amount = resumo.get('direct_amount', 0.0)
                indirect_amount = resumo.get('indirect_amount', 0.0)
                total_amount = resumo.get('total_amount', 0.0)
                direct_units_quantity = resumo.get('direct_units_quantity', 0)
                indirect_units_quantity = resumo.get('indirect_units_quantity', 0)
                units_quantity = resumo.get('units_quantity', 0)
                direct_items_quantity = resumo.get('direct_items_quantity', 0)
                indirect_items_quantity = resumo.get('indirect_items_quantity', 0)
                advertising_items_quantity = resumo.get('advertising_items_quantity', 0)
                organic_units_quantity = resumo.get('organic_units_quantity', 0)
                organic_items_quantity = resumo.get('organic_items_quantity', 0)
                acos = resumo.get('acos', 0.0)
                organic_units_amount = resumo.get('organic_units_amount', 0.0)
                sov = resumo.get('sov', 0.0)
                ctr = resumo.get('ctr', 0.0)
                cvr = resumo.get('cvr', 0.0)
                roas = resumo.get('roas', 0.0)
                date = resumo.get('date', 'N/A')

                cur.execute('''
                INSERT INTO anuncios_metricas_diarias (id_anuncio, item_id, title,clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, 
                indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos,
                organic_amount,sov, ctr, cvr, roas, date, usuario_id_anuncios_metricas_diarias) VALUES (%s,%s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s,%s, %s, %s,%s, %s, %s, %s, %s,%s, %s, %s, %s, %s)
                ''', (
                item_id, item_id, title,clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity,
                indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos, organic_units_amount,sov, ctr, cvr, roas, date, usuario_id,))
            conn.commit()
            print('----------------------------------------\n\n')
        url='https://api.mercadolibre.com/advertising/advertisers?product_id=PADS'
        headers = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '1',
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        advertisers = response.json()
        if response.status_code not in [200, 206]:
            print(f"Erro ao buscar anunciantes: {advertisers.get('message', 'Erro desconhecido')}")
            continue
        for advertiser in advertisers.get('advertisers', []):
            advertiser_id = advertiser.get('advertiser_id', 'N/A')
            print(f"Anunciante ID: {advertiser_id}")
            headers = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
        }
            url=f'https://api.mercadolibre.com/advertising/advertisers/{advertiser_id}/product_ads/campaigns?limit=1&offset=0'
            response = requests.get(url, headers = headers)
            resp = response.json()  
            paging = resp.get('paging', {})
            total_campanhas = paging.get('total', 0)
            for offset in range(0, total_campanhas):
                url=f'https://api.mercadolibre.com/advertising/advertisers/{advertiser_id}/product_ads/campaigns?limit=1&offset={offset}' 
                response = requests.get(url, headers = headers)
                if response.status_code not in [200, 206]:
                    print(f"Erro ao buscar campanhas do anunciante {advertiser_id} com offset {offset}: {response.text}")
                    continue
                resp = response.json()
                result= resp.get('results', [])
                for campanha in result:
                    print(f"Campanha: {campanha.get('id')}")
                    print("Nome da campanha: ", campanha.get('name', None))
                    campanha_id = campanha.get('id', None)
                    nome= campanha.get('name', None)
                    status = campanha.get('status', None)
                    strategy = campanha.get('strategy', None)
                    budget = campanha.get('budget', 0.0)
                    currency_id = campanha.get('currency_id', None)
                    last_updated = campanha.get('last_updated', None)
                    if last_updated:
                        last_updated = datetime.fromisoformat(last_updated.replace('Z','')).date()
                    print('last_updated', last_updated)
                    date_created = datetime.fromisoformat(campanha.get('date_created', None).replace('Z','')).date()
                    print('date_created',date_created)
                    print("ontem")
                    channel= campanha.get('channel', None)
                    acos_target = campanha.get('acos_target', 0.0)
                    if date_created.strftime('%Y-%m-%d') == ontem.strftime('%Y-%m-%d'):
                        print("Inserindo nova campanha no banco de dados")
                        cur.execute('''INSERT INTO campanhas (campanha_id,nome,status,strategy,budget,currency_id,last_updated,date_created,usuario_id_campanhas,channel,acos_target)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(campanha_id,nome,status,strategy,budget,currency_id,last_updated,date_created,usuario_id,acos_target,))
                        print(f'campanha: {campanha_id}, inserida com sucesso')
                    elif last_updated.strftime('%Y-%m-%d') == ontem.strftime('%Y-%m-%d'):
                        print(f"Atualizando campanha {campanha_id} com os dados mais recentes")
                        cur.execute('''UPDATE campanhas SET nome = %s, status = %s, strategy=%s,
                        budget = %s, last_updated = %s, channel = %s, acos_target = %s WHERE campanha_id = %s 
                        AND usuario_id_campanhas = %s''',(nome, status, strategy, budget, last_updated, channel, acos_target, campanha_id, usuario_id,))
                        print(f'campanha: {campanha_id}, atualizada com sucesso')
                    conn.commit()
                    #Campanhas Metricas diarias abaixo:
        cur.execute('SELECT campanha_id,nome FROM campanhas WHERE usuario_id_campanhas = %s', (usuario_id,))
        for campanhas in cur.fetchall():
            campanha_id = campanhas['campanha_id']
            nome = campanhas['nome']
            if status == 'active':
                url_campanhas_diaria = f"https://api.mercadolibre.com/advertising/product_ads/campaigns/{campanha_id}?date_from={ontem.strftime('%Y-%m-%d')}&date_to={ontem.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount,impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark&aggregation_type=DAILY"
                response_campanhas_diaria = requests.get(url_campanhas_diaria, headers=headers)
                if response_campanhas_diaria.status_code not in [200, 206]:
                    print("Erro ao buscar métricas diárias da campanha:", response_campanhas_diaria.text)
                    return response_campanhas_diaria.status_code
                campanhas_diaria_data = response_campanhas_diaria.json() 
                results_diaria = campanhas_diaria_data.get('results', [])
                for result_diaria in results_diaria:
                    clicks = result_diaria.get('clicks', 0)
                    prints = result_diaria.get('prints', 0)
                    cost = result_diaria.get('cost', 0.0)
                    cpc = result_diaria.get('cpc', 0.0)
                    ctr = result_diaria.get('ctr', 0.0)
                    direct_amount = result_diaria.get('direct_amount', 0.0)
                    indirect_amount = result_diaria.get('indirect_amount', 0.0)
                    total_amount = result_diaria.get('total_amount', 0.0)
                    direct_units_quantity = result_diaria.get('direct_units_quantity', 0)
                    indirect_units_quantity = result_diaria.get('indirect_units_quantity', 0)
                    units_quantity = result_diaria.get('units_quantity', 0)
                    direct_items_quantity = result_diaria.get('direct_items_quantity', 0)
                    indirect_items_quantity = result_diaria.get('indirect_items_quantity', 0)
                    advertising_items_quantity = result_diaria.get('advertising_items_quantity', 0)
                    organic_units_quantity = result_diaria.get('organic_units_quantity', 0)
                    organic_units_amount = result_diaria.get('organic_units_amount', 0.0)
                    organic_items_quantity = result_diaria.get('organic_items_quantity', 0)
                    acos = result_diaria.get('acos', 0.0)
                    cvr = result_diaria.get('cvr', 0.0)
                    roas = result_diaria.get('roas', 0.0)
                    sov = result_diaria.get('sov', 0.0)
                    impression_share = result_diaria.get('impression_share', 0.0)
                    top_impression_share = result_diaria.get('top_impression_share', 0.0)
                    lost_impression_share_by_budget = result_diaria.get('lost_impression_share_by_budget', 0.0)
                    lost_impression_share_by_ad_rank = result_diaria.get('lost_impression_share_by_ad_rank', 0.0)
                    acos_benchmark = result_diaria.get('acos_benchmark', 0.0)
                    date = result_diaria.get('date', 'N/A')
                    print(f"Data: {date}, Cliques: {clicks}, Impressões: {prints}, Custo: {cost}")
                    print(f"CPC: {cpc}, CTR: {ctr}, Quantidade de unidades diretas: {direct_units_quantity}, Quantidade de unidades indiretas: {indirect_units_quantity}")
                    print(f"Quantidade total de unidades: {units_quantity}, Quantidade de itens diretos: {direct_items_quantity}, Quantidade de itens indiretos: {indirect_items_quantity}")
                    print(f"Quantidade de itens publicitários: {advertising_items_quantity}, Quantidade de unidades orgânicas: {organic_units_quantity}, Quantidade de montante orgânico: {organic_units_amount}")
                    print(f"Quantidade de itens orgânicos: {organic_items_quantity}, ACOS: {acos}, CVR: {cvr}, ROAS: {roas}, SOV: {sov}")
                    print(f"Participação de impressões: {impression_share}, Participação de impressões no topo: {top_impression_share}")
                    print(f"Participação de impressões perdidas por orçamento: {lost_impression_share_by_budget}, Participação de impressões perdidas por classificação do anúncio: {lost_impression_share_by_ad_rank}")
                    print(f"ACOS Benchmark: {acos_benchmark}")



                    cur.execute('''
                    INSERT INTO campanhas_metricas_diarias (campanha_id, nome,clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,
                    total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,
                    organic_units_quantity, organic_amount, organic_items_quantity, acos,cvr, roas, sov, impression_share, top_impression_share,
                    lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark, date, usuario_id_campanhas_metricas_diarias)
                    VALUES (
                    %s, %s, %s, %s,%s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s)''', (
                    campanha_id, nome,clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,
                    direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_units_amount, organic_items_quantity, acos,
                    cvr, roas, sov, impression_share, top_impression_share,lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark, date, usuario_id,))
                    conn.commit()


def promocoes(user_id, access_token,id_ml):
    try:
        print(f"Consultando promoções do usuário")
        conn= get_db_connection()
        cur = conn.cursor() 
        url_promocoes = f"https://api.mercadolibre.com/seller-promotions/users/{id_ml}?app_version=v2"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        TYPES_NO_DETAILS = ["DOD", "LIGHTNING", "PRICE_DESCOUNT",]
        response = requests.get(url_promocoes, headers=headers)
        respostas = response.json()
        if response.status_code not in [200,206]:
            return 
        paging= respostas.get('paging', {})
        total= paging.get('total', 0)
        limit= paging.get('limit', 0)
        for offset in range(0,total,limit):
            url_promocoes = f"https://api.mercadolibre.com/seller-promotions/users/{id_ml}?app_version=v2&offset={offset}&limit={limit}"
            response = requests.get(url_promocoes, headers=headers)
            if response.status_code not in [200, 206]:
                continue
            respostas = response.json()
            for resposta in respostas.get('results', []):
                id_promotion = resposta.get('id', None)
                type_promotion = resposta.get('type', None)
                status = resposta.get('status', None)
                finish_date = resposta.get('finish_date')
                start_date = resposta.get('start_date', None)
                deadline = resposta.get('deadline_date', None)
                name = resposta.get('name', None)
                cur.execute('INSERT INTO promotion (id_promotion,type_promotion,status,finish_date,start_date,deadline_date,name, usuario_id_promotions) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id_promotion) DO NOTHING',(id_promotion, type_promotion, status, finish_date, start_date, deadline, name,user_id,))
                conn.commit()
                if type_promotion == 'MARKET_PLACE_CAMPAIGN':
                    benefits = resposta.get('benefits', {})
                    if benefits:
                        meli_percent = benefits.get('meli_percent', None)
                        seller_percent = benefits.get('seller_percent', None)
                        benefits_type = benefits.get('type', None)
                        cur.execute('INSERT INTO market_place_campaign_type_promotion (id_promotion, type_promotion, type_benefits, meli_percent,seller_percent,usuario_id_marketplace_campaign_type_promotion) VALULES (%s,%s,%s,%s,%s,%s)',(id_promotion, type_promotion, benefits_type, meli_percent, seller_percent,user_id,))
    
                elif type_promotion == 'PRE_NEGOTIATED' or type_promotion == 'UNHEALTHY_STOCK':
                    offers = resposta.get('offers',[])
                    for offer in offers:
                        offer_id = offer.get('id', None)
                        original_price = offer.get('original_price', None)
                        new_price = offer.get('new_price', None)
                        status_offer = offer.get('status', None)
                        start_date_offer = offer.get('start_date', None)
                        end_date_offer = offer.get('end_date', None)
                        benefits = offer.get('benefits', {})
                        meli_percent = benefits.get('meli_percent', None)
                        seller_percent = benefits.get('seller_percent', None)
                        benefits_type = benefits.get('type', None)
                        cur.execute('''INSERT INTO pre_negotiated_type_promotion_offers (id_promotion,type_promotion, 
                        offer_id,type_benefits, meli_percent, seller_percent, start_date, end_date, status, 
                        original_price, new_price, usuario_id_pre_negotiated_type_promotion_offers) 
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(id_promotion,type_promotion, offer_id, benefits_type, meli_percent, seller_percent, start_date_offer, end_date_offer, status_offer, original_price, new_price,user_id,))
                elif type_promotion == 'SELLER_COUPON_CAMPAIGN':
                    sub_type = resposta.get('sub_type', None)
                    fixed_amount = resposta.get('fixed_amount', None)
                    min_purchase_amount = resposta.get('min_purchase_amount',None)
                    max_purchase_amount = resposta.get('max_purchase_amount', None)
                    coupon_code = resposta.get('coupon_code', None)
                    redeems_per_user = resposta.get('redeems_per_user', None)
                    budget = resposta.get('budget',None)
                    remaining_budget = resposta.get('remaining_budget', None)
                    used_coupons = resposta.get('used_coupons', None)
                    fixed_percentage = resposta.get('fixed_percentage', None)
                    cur.execute('''INSERT INTO seller_coupon_campaign_type_promotion (id_promotion,type_promotion,sub_type, fixed_amount, min_purchase_amount, max_purchase_amount, coupon_code, redeems_per_user,
                    budget, remaining_budget, used_coupons, fixed_coupons, usuario_id_seller_coupon_campaign_type_promotion) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(id_promotion,type_promotion,sub_type,
                    fixed_amount,min_purchase_amount,max_purchase_amount,coupon_code,redeems_per_user, budget, remaining_budget, used_coupons, fixed_percentage, user_id,))
    
                elif type_promotion == 'VOLUME':
                    buy_quantity = resposta.get('buy_quantity', None)
                    pay_quantity= resposta.get('pay_quantity', None)
                    allow_combination = resposta.get('allow_combination', None)
                    sub_type = resposta.get('sub_type', None)
                    cur.execute('''INSERT INTO volume_type_promotion (id_promotion,type_promotion,buy_quantity, pay_quantity, sub_type, allow_combination, usuario_id_volume_type_promotion) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (id_promotion, type_promotion, buy_quantity, pay_quantity, sub_type, allow_combination, user_id ,))
                url = f'https://api.mercadolibre.com/seller-promotions/promotions/{id_promotion}/items?promotion_type={type_promotion}&app_version=v2'
                response = requests.get(url, headers=headers) 
                if response.status_code not in [200]:
                    continue      
                resp = response.json()
                if not resp.get('results', None):
                    continue
                for result in resp.get('results'):
                    id_promotion_item = id_promotion
                    item_id = result.get('id', None)
                    status = result.get('status', None)
                    price = result.get('price', None)
                    original_price = result.get('original_price', None)
                    min_discounted_price= result.get('min_discounted_price', None)
                    max_discounted_price= result.get('max_discounted_price', None)
                    suggested_discounted_price= result.get('suggested_discounted_price', None)
                    start_date= result.get('start_date', None)
                    end_date = result.get('end_date', None)
                    sub_type = result.get('sub_type', None)
                    offer_id = result.get('offer_id', None)
    
                    meli_percentage = result.get('meli_percentage', None)
                    seller_percentage = result.get('seller_percentage', None)
                    buy_quantity = result.get('buy_quantity', None)
                    pay_quantity = result.get('pay_quantity', None)
                    allow_combination = result.get('allow_combination', None)
                    fixed_amount = result.get('fixed_amount', None)
                    fixed_percentage = result.get('fixed_percentage', None)
                    top_deal_price = result.get('top_deal_price', None)
                    discount_percentage = result.get('descount_percentage', None)
                    cur.execute("""INSERT INTO ponte_item_promotions (id_promotion, item_id, status, price, original_price, 
                                min_discounted_price,max_discounted_price, suggested_discounted_price, start_date, end_date, sub_type, offer_id, meli_percentage, 
                                seller_percentage, buy_quantity, pay_quantity, allow_combination, fixed_amount, fixed_percentage, top_deal_price, 
                                discount_percentage, usuario_id_ponte_item_promotions, auto) VALUES (%s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s,%s)""",(id_promotion_item, item_id, status, price, original_price, 
                                min_discounted_price,max_discounted_price ,suggested_discounted_price, start_date, end_date,sub_type, offer_id, meli_percentage, 
                                seller_percentage, buy_quantity, pay_quantity, allow_combination, fixed_amount, fixed_percentage, top_deal_price, 
                                discount_percentage, user_id,False))
    
    
        conn.commit()         
        cur.close()
        conn.close()
    except Exception as e:
        print(f'erro: {str(e)}')
    print('Terminou de pegar as promocoes')


def listar_novas_conversas_pos_venda():
    print("Entrou na função listar_novas_conversas_pos_venda")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT usuario_id, acess_token FROM contas_mercado_livre")
    contas = cur.fetchall()
    for conta in contas:
        user_id = conta['usuario_id']
        access_token = conta['acess_token']
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        ml_response = requests.get("https://api.mercadolibre.com/users/me", headers=headers)
        response_ml=ml_response.json()
        id_ml=response_ml['id']
        print(f"Processando conta ID: {id_ml}, User ID: {user_id}")
        try:
            listar_conversas_pos_venda(user_id,id_ml,access_token)
        except Exception as e:
            print(f"Erro ao listar conversas pós-venda para a conta ID {id_ml}: {e}")


@app.route('/')
def home():
    return 'Flask rodando! (Função periódica em background)'

def minha_tarefa():
    print("Rodando tarefa de atualização diária às 00:00")
    pegar_anuncios_e_campanhas_diario()

# Scheduler que roda todos os dias meia noite
scheduler = BackgroundScheduler(timezone="America/Sao_Paulo")
scheduler.add_job(minha_tarefa, CronTrigger(hour=0, minute=0, second=0))
scheduler.start()

def pegar_anuncios_e_campanhas_diario():
    print('Entrou em campanhas e anuncios diarios')
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT i.item_id as item_id, i.title as title,i.usuario_id_anuncios as user_id,a.acess_token as access_token, a.refresh_token as refresh_token,a.expiracao_token as expiracao_token FROM anuncios i JOIN contas_mercado_livre a ON i.usuario_id_itens=a.usuario_id")
            rows_dict_anuncios=cur.fetchall()
            cur.execute("SELECT c.campanha_id as campanha_id, c.usuario_id_campanhas as user_id, a.acess_token as access_token, a.refresh_token as refresh_token, a.expiracao_token as expiracao_token FROM campanhas c JOIN contas_mercado_livre a ON c.usuario_id_campanhas=a.usuario_id WHERE c.status=%s", 'active')
            rows_dict_campanhas=cur.fetchall()
        for i in rows_dict_anuncios:
            now = datetime.utcnow()
            item_id=i['item_id']
            user_id=i['user_id']
            title=i['title']
            if i and i['expiracao_token'] and now > i['expiracao_token']:
                app.logger.info("Token expirado, renovando...")
                dados = renovar_access_token(i["refresh_token"])
                access_token = dados["access_token"]
                cur.execute("""
                    UPDATE contas_mercado_livre
                    SET acess_token=%s,
                        refresh_token=%s,
                        expiracao_token=%s
                    WHERE usuario_id=%s
                """, (dados["access_token"], dados["novo_refresh_token"],
                    dados["nova_expiracao"], user_id))
                conn.commit()
            else:
                access_token=i['access_token']
            headers = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
            }
            final = datetime.now().date()
            inicio = final - timedelta(days=1) 
            url_metricas_anuncios_ontem=f"https://api.mercadolibre.com/advertising/product_ads/items/{item_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount&aggregation_type=DAILY"
            response_summary = requests.get(url_metricas_anuncios_ontem, headers=headers)
            if response_summary.status_code not in [200, 206]:
                return response_summary.status_code
            resumo_data = response_summary.json()

            results_resumo = resumo_data.get('results', [])
            for resumo in results_resumo:
                clicks = resumo.get('clicks', 0)
                prints = resumo.get('prints', 0)
                cost = resumo.get('cost', 0.0)
                cpc = resumo.get('cpc', 0.0)
                direct_amount = resumo.get('direct_amount', 0.0)
                indirect_amount = resumo.get('indirect_amount', 0.0)
                total_amount = resumo.get('total_amount', 0.0)
                direct_units_quantity = resumo.get('direct_units_quantity', 0)
                indirect_units_quantity = resumo.get('indirect_units_quantity', 0)
                units_quantity = resumo.get('units_quantity', 0)
                direct_items_quantity = resumo.get('direct_items_quantity', 0)
                indirect_items_quantity = resumo.get('indirect_items_quantity', 0)
                advertising_items_quantity = resumo.get('advertising_items_quantity', 0)
                organic_units_quantity = resumo.get('organic_units_quantity', 0)
                organic_items_quantity = resumo.get('organic_items_quantity', 0)
                acos = resumo.get('acos', 0.0)
                organic_units_amount = resumo.get('organic_units_amount', 0.0)
                sov = resumo.get('sov', 0.0)
                ctr = resumo.get('ctr', 0.0)
                cvr = resumo.get('cvr', 0.0)
                roas = resumo.get('roas', 0.0)
                date = resumo.get('date', 'N/A')    

                cur.execute('''
                INSERT INTO anuncios_metricas_diarias (id_anuncio, item_id, clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, 
                indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos,
                organic_amount,sov, ctr, cvr, roas, date,title, usuario_id_anuncios_metricas_diarias) VALUES (%s,%s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s,%s, %s, %s,%s, %s, %s, %s, %s,%s, %s, %s, %s, %s)
                ''', (
                item_id, item_id, clicks, prints, cost, cpc, direct_amount, indirect_amount, total_amount,direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity,
                indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_items_quantity, acos, organic_units_amount,sov, ctr, cvr, roas, date, title, user_id,))
            conn.commit()
        for a in rows_dict_campanhas:
            now=datetime.utcnow()
            user_id=a['user_id']
            if a['expiracao_token'] and now > a['expiracao_token']:
                app.logger.info("Token expirado, renovando...")
                dados = renovar_access_token(a["refresh_token"])
                access_token = dados["access_token"]
                cur.execute("""
                    UPDATE contas_mercado_livre
                    SET acess_token=%s,
                        refresh_token=%s,
                        expiracao_token=%s
                    WHERE usuario_id=%s
                """, (dados["access_token"], dados["novo_refresh_token"],
                    dados["nova_expiracao"], user_id))
                conn.commit()
            else:
                access_token=a['access_token']
            headers = {
            "Authorization": f"Bearer {access_token}",
            'api-version': '2',
            }
            final = datetime.now().date()
            inicio = final - timedelta(days=1) 
            url_campanhas_diaria = f"""https://api.mercadolibre.com/advertising/product_ads/campaigns/{campanha_id}?date_from={inicio.strftime('%Y-%m-%d')}&date_to={final.strftime('%Y-%m-%d')}&metrics=clicks,prints,ctr,cost,cpc,acos,organic_units_quantity,organic_units_amount,organic_items_quantity,direct_items_quantity,indirect_items_quantity,advertising_items_quantity,cvr,roas,sov,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount,impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark&aggregation_type=DAILY"""
            response_campanhas_diaria = requests.get(url_campanhas_diaria, headers=headers)
            if response_campanhas_diaria.status_code not in [200, 206]:
                return response_campanhas_diaria.status_code
            campanhas_diaria_data = response_campanhas_diaria.json() 
            results_diaria = campanhas_diaria_data.get('results', [])
            for result_diaria in results_diaria:
                clicks = result_diaria.get('clicks', 0)
                prints = result_diaria.get('prints', 0)
                cost = result_diaria.get('cost', 0.0)
                cpc = result_diaria.get('cpc', 0.0)
                ctr = result_diaria.get('ctr', 0.0)
                direct_amount = result_diaria.get('direct_amount', 0.0)
                indirect_amount = result_diaria.get('indirect_amount', 0.0)
                total_amount = result_diaria.get('total_amount', 0.0)
                direct_units_quantity = result_diaria.get('direct_units_quantity', 0)
                indirect_units_quantity = result_diaria.get('indirect_units_quantity', 0)
                units_quantity = result_diaria.get('units_quantity', 0)
                direct_items_quantity = result_diaria.get('direct_items_quantity', 0)
                indirect_items_quantity = result_diaria.get('indirect_items_quantity', 0)
                advertising_items_quantity = result_diaria.get('advertising_items_quantity', 0)
                organic_units_quantity = result_diaria.get('organic_units_quantity', 0)
                organic_units_amount = result_diaria.get('organic_units_amount', 0.0)
                organic_items_quantity = result_diaria.get('organic_items_quantity', 0)
                acos = result_diaria.get('acos', 0.0)
                cvr = result_diaria.get('cvr', 0.0)
                roas = result_diaria.get('roas', 0.0)
                sov = result_diaria.get('sov', 0.0)
                impression_share = result_diaria.get('impression_share', 0.0)
                top_impression_share = result_diaria.get('top_impression_share', 0.0)
                lost_impression_share_by_budget = result_diaria.get('lost_impression_share_by_budget', 0.0)
                lost_impression_share_by_ad_rank = result_diaria.get('lost_impression_share_by_ad_rank', 0.0)
                acos_benchmark = result_diaria.get('acos_benchmark', 0.0)
                date = result_diaria.get('date', 'N/A')



                cur.execute('''
                INSERT INTO campanhas_metricas_diarias (campanha_id, clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,
                total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,direct_items_quantity, indirect_items_quantity, advertising_items_quantity,
                organic_units_quantity, organic_amount, organic_items_quantity, acos,cvr, roas, sov, impression_share, top_impression_share,
                lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark,nome, date, usuario_id_campanhas_metricas_diarias)
                VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s,%s)''', (
                campanha_id, clicks, prints, cost, cpc, ctr, direct_amount, indirect_amount,total_amount, direct_units_quantity, indirect_units_quantity, units_quantity,
                direct_items_quantity, indirect_items_quantity, advertising_items_quantity,organic_units_quantity, organic_units_amount, organic_items_quantity, acos,
                cvr, roas, sov, impression_share, top_impression_share,lost_impression_share_by_budget, lost_impression_share_by_ad_rank,acos_benchmark, name,date, user_id,))
    except Exception as e:
        print('Erro: ', str(e))

def listar_todos_itens(user_id,id,access_token):
    try:
        print("Entrou na função listar_todos_itens")
        url=f"https://api.mercadolibre.com/users/{id}/items/search"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code not in [200, 206]:
            return False
        itens = response.json()
        itens_paging = itens.get('paging', {})
        total = itens_paging.get('total', 0)
        limit = itens_paging.get('limit', 0)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT item_id FROM itens WHERE usuario_id_item=%s", (user_id,))
        itens_existentes = set()
        for linha in cur.fetchall():
            itens_existentes.add(linha['item_id'])
        for offset in range(0, total, limit):
            url=f"https://api.mercadolibre.com/users/{id}/items/search?offset={offset}&limit={limit}"
            response = requests.get(url, headers=headers)
            if response.status_code not in [200]:
                continue
            itens = response.json()
            for item_id in itens.get('results', []):
                if item_id not in itens_existentes:
                    url_item = f"https://api.mercadolibre.com/items/{item_id}"
                    url_descricao = f"https://api.mercadolibre.com/items/{item_id}/description"
                    response_descricao = requests.get(url_descricao, headers=headers)
                    resposta_descricao = response_descricao.json()
    
                    response_item = requests.get(url_item, headers=headers)
                    if response_item.status_code not in [200, 206]:
                        continue
                    resposta_itens = response_item.json()
                    category_id = resposta_itens.get('category_id', 'N/A')
                    url_cateogira=f'https://api.mercadolibre.com/categories/{category_id}'
                    categoria_dados= requests.get(url_cateogira, headers=headers)
                    categoria_json = categoria_dados.json()
                    categoria = categoria_json.get('name', 'N/A')
                    nome_item = resposta_itens.get('title', 'Sem título').strip()
                    tipo_ad = resposta_itens.get('listing_type_id', 'sem tipo ad')
                    quantidade = resposta_itens.get('available_quantity', 0)
                    preco = resposta_itens.get('price', 0.0)
                    status = resposta_itens.get('status')
                    preco_original = resposta_itens.get('original_price', 0.0)
                    preco_base = resposta_itens.get('base_price', 0.0)
                    descricao = resposta_descricao.get('plain_text', 'Sem descrição')
                    imagens = resposta_itens.get('pictures', [])
                    imagem = [img['url'] for img in imagens] if imagens else ['Sem imagem']
                    try:
                        cur.execute(
                            'INSERT INTO itens (usuario_id_item, item_id, nome_item, quantidade, preco, status,descricao, imagem, preco_original, preco_base,disponivel,tipo_ad,categoria) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (item_id) DO NOTHING',
                            (user_id, item_id, nome_item, quantidade, preco, status,descricao, imagem, preco_original, preco_base,True,tipo_ad,categoria)
                        )
                        conn.commit()
                    except Exception as e:
                        print(f"Erro ao inserir item {item_id} no banco: {e}")
    except Exception as e:
        print(f'erro: {str(e)}')   
    print('Terminou de pegar os itens')

def listar_conversas_pre_venda(user_id,id,access_token):
    try:
        print("entrou no listar_conversas")
        url = f"https://api.mercadolibre.com/questions/search?seller_id={id}&api_version=4"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        pages = response.json()
        if response.status_code not in [200, 206]:
            return []
    
        total_pages = pages.get("total", 0)
        for offset in range(0, total_pages, 50):
            url_recentes = f"https://api.mercadolibre.com/questions/search?seller_id={id}&api_version=4&limit=50&offset={offset}"
            respons = requests.get(url_recentes, headers=headers)
            time.sleep(0.3)  # Atraso de 300ms entre as requisições
            if respons.status_code not in [200, 206]:
                print('ERRO ao tentar pegar uma mensagem pre-venda')  
                continue
            conversas=respons.json()
            conn=get_db_connection()
            cur=conn.cursor()
            cur.execute("SELECT client_name, message FROM messages WHERE usuario_id_messages=%s AND type=%s",(user_id,'pre_sale',))
            clientes_existentes=[]
            mensagens_existentes=[]
            comparar=cur.fetchall()
            if comparar:
                clientes_existentes=[linha['client_name'] for linha in comparar]
                mensagens_existentes=[linha['message'] for linha in comparar]
            for m in conversas['questions']:
                if m:
                    form=m.get('from')
                    if isinstance(form , dict) and form.get("id"):
                        cliente_id=form.get('id')
    
                        cliente_nome = buscar_nome(cliente_id, access_token)
                    status=''
                    if m.get('status'):
                        status = m.get('status', 'N/A')
                    if m.get('item_id'):
                        item_id=m.get('item_id')
                    if m.get('text') and m.get('date_created'):
                        mensagem = m['text']
                        data_envi = m['date_created']
                        data_envio = converter_zona_pro_brasil(data_envi)
                    
                        if not comparar or (( cliente_id not in clientes_existentes) and  (mensagem not in mensagens_existentes)):
                            cur.execute(
                               """
                        INSERT INTO messages
                          (client_name, message, date_created, author, type, item_id, status, usuario_id_messages)
                        SELECT %s, %s, %s, %s, %s, %s, %s, %s
                        WHERE EXISTS (
                          SELECT 1 FROM itens i
                          WHERE i.item_id = %s
                            AND i.usuario_id_item = %s
                        );
                        """,(cliente_nome['nickname'], mensagem, data_envio, 'buyer', 'pre_sale',
                            item_id, status, user_id,
                            item_id, user_id,))
    
                    answer = m.get('answer')
                    if isinstance(answer, dict) and answer.get('text') and answer.get('date_created'):
                        resposta = answer['text']
                        status = answer.get('status', 'N/A')
                        data_envi = answer['date_created']
                        data_envio = converter_zona_pro_brasil(data_envi)
                        if not comparar or ((cliente_id not in clientes_existentes) and  (mensagem not in mensagens_existentes)):
                            cur.execute(
                               """
                        INSERT INTO messages
                          (client_name, message, date_created, author, type, item_id, status, usuario_id_messages)
                        SELECT %s, %s, %s, %s, %s, %s, %s, %s
                        WHERE EXISTS (
                          SELECT 1 FROM itens i
                          WHERE i.item_id = %s
                            AND i.usuario_id_item = %s
                        );
                        """,(cliente_nome['nickname'], resposta, data_envio, 'seller', 'pre_sale',
                            item_id, status, user_id,
                            item_id, user_id,))
    
                    conn.commit()
        conn.close()
        cur.close()
    except Exception as e:
        print(f'erro: {str(e)}')
    print('Terminou de pegar as mensagens pre-venda') 


def buscar_nome(id_do_cliente,access_token):
    url=f"https://api.mercadolibre.com/users/{id_do_cliente}"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    return response.json()

# 🔹 Função para gerar o code_verifier (PKCE)
def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(64)).decode('utf-8').rstrip('=')

# 🔹 Função para gerar o code_challenge baseado no code_verifier
def generate_code_challenge(code_verifier):
    sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
def gerar_token(user_id):
    print('entrou no gerar token')
    token = create_access_token(identity=str(user_id), expires_delta=timedelta(hours=2))
    return token
def renovar_access_token(refresh_token):
    print("entrou no renovar_token")
    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    response = requests.post(url, data=payload)
    token_data = response.json()
    if 'access_token' in token_data:
        print("encontrou o accesstoken:", token_data["access_token"])
        novo_access_token=token_data["access_token"]
        novo_refresh_token=token_data.get('refresh_token',refresh_token)
        print('novo refresh :',novo_refresh_token)
        expires_in=token_data['expires_in']
        nova_expiracao=datetime.now()+timedelta(seconds=expires_in)
    print("retornou")
    return {"access_token":novo_access_token,"novo_refresh_token":novo_refresh_token,"nova_expiracao":nova_expiracao}




# 🔥 3️⃣ Callback para capturar código de autorização e obter Access Token



def getApiMercadoLivre(data):
    print("entoru no getAPi do mercado livre")
    print("token:",data)
    decoded_token=decode_token(data)
    user_id=decoded_token.get('sub')
    conn=get_db_connection()
    cur=conn.cursor()
    cur.execute("SELECT acess_token FROM contas_mercado_livre WHERE usuario_id=%s",(user_id,))
    token_access=cur.fetchone()
    access_token=token_access['acess_token']
    headers = {
            "Authorization": f"Bearer {access_token}"
        }
    ml_response = requests.get("https://api.mercadolibre.com/users/me", headers=headers)
    response_ml=ml_response.json()
    id_ml=response_ml['id']
    cur.execute("UPDATE contas_mercado_livre SET id_ml=%s WHERE usuario_id=%s",(id_ml,user_id,))
    conn.commit()
    cur.close()
    #listar_conversas_pos_venda(user_id,id_ml,access_token)
    #listar_conversas_pre_venda(user_id,id_ml,access_token)
    listar_todos_itens(user_id,id_ml,access_token)
    return True

import pytz
from dateutil import parser
def converter_zona_pro_brasil(ml_date):
    dt = parser.parse(ml_date)


    # Ajusta para o Brasil
    br_timezone = pytz.timezone('America/Sao_Paulo')
    return dt.replace(tzinfo=pytz.utc).astimezone(br_timezone)




def teste_itens_promovidos(access_token):
    print("Entrou na função teste_itens_promovidos")
    conn= get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT item_id FROM itens")
    itens = cur.fetchall()
    cont_certos = 0
    cont_errados = 0
    headers_url = {
        "Authorization": f"Bearer {access_token}",
        'api-version': '2',
    }
    for i,item in enumerate(itens):
        item_id = item['item_id']
        print(f"item_id: {item_id}")
        print (f'item {i}: ', end='')
        try:
            url = f"https://api.mercadolibre.com/advertising/product_ads/items/{item_id}"
            response = requests.get(url, headers=headers_url)
        except requests.exceptions.RequestException as e:
            print(f"Erro ao fazer requisição para o item {item_id}: {e}")
            cont_errados += 1
            continue

        if response.status_code not in [200, 206]:
            print(f"Erro ao buscar anúncios promovidos para o item {item_id}: {response.text}")
            continue
            cont_errados += 1
        cont_certos +=1
        data = response.json()
        listingtype_id = data.get('listing_type_id', 'N/A')
        price = data.get('price', 0.0)
        print(f"title", data.get('title', 'N/A'))
        print(f"status: {data.get('status', 'N/A')}")
        print(f"has_discount: {data.get('has_discount', 'N/A')}")
        print(f"condition : {data.get('condition')}, 'N/A')")
        print(f"Total de itens processados: {len(itens)}"
        f"\nItens com sucesso: {cont_certos} \nItens com erro: {cont_errados}")










def chat_pos_venda(mensagem: str, nome: str,descricao:str, contexto:str) -> str:
    print("entrou no chat")
    try:
      modelo=ChatOpenAI(model='gpt-4o-mini')
      if contexto == 'nao existe':
        prompt=ChatPromptTemplate.from_template('Você é um vendedor do mercado livre, responda a seguinte pergunta:{pergunta}, este é o nome do item:{nome} e a sua descricao:{descricao}')
        chain= prompt | modelo | StrOutputParser()
        print(chain.invoke({'pergunta': mensagem, 'nome':nome,'descrição':descricao}))
      else:
        prompt=ChatPromptTemplate.from_template('você é um vendedor do mercado livre, responda a seguinte pergunta :{pergunta},este é o nome do item:{nome} e a sua descricao:{descricao},  com base nesse contexto de conversa: {contexto}')
        chain= prompt | modelo | StrOutputParser()
        print(chain.invoke({'pergunta':mensagem,'nome':nome,'descricao':descricao,'contexto':contexto}))

    except Exception as e:
        print("Erro na OpenAI:", e)
        return ""


def chat_novai_manager_separador_de_pergunta():



    model = ChatOpenAI(model='gpt-4o-mini')
    prompt = ChatPromptTemplate.from_template('''
Você é um assistente que organiza perguntas feitas por vendedores do Mercado Livre para um sistema de IA que responde com base nos dados do vendedor.

Sua tarefa é:
- Identificar se há mais de uma pergunta.
- Verificar se as perguntas são dependentes (precisam ser respondidas juntas) ou independentes (podem ser respondidas separadamente).
- Juntar perguntas dependentes em uma só.
- Separar perguntas independentes e adicionar contexto se necessário.
- Devolver uma lista com as perguntas ajustadas.

Exemplos:

Usuário: "Qual meu item mais vendido na quarta-feira? Qual a sua descrição?"
Resposta: [ "Qual o nome e a descrição do meu item mais vendido na quarta-feira?" ]

Usuário: "Qual item eu mais recebo mensagem e qual item eu mais vendo no mês de julho."
Resposta: [
  "Qual item eu mais recebo mensagem no mês de julho?",
  "Qual item eu mais vendo no mês de julho?"
]

Agora analise a seguinte mensagem e retorne as perguntas ajustadas no formato de lista:
#{mensagem}
''')
    class EncaminharNeuronio(BaseModel):
        '''Separar mensagens inteligentemente'''
        resp: list[str] = Field(description='lista com as perguntas ajustadas')
    chain = prompt | model.with_structured_output(EncaminharNeuronio)
    resposta = chain.invoke({'mensagem':mensagem})
    print('resposta do primeiro neuronio: ', resposta)
    informacao_final=[]
    for i in resposta.resp:
        informacao_final.append(chat_novai_manager_pilot(i,user_id))
    prompt= ChatPromptTemplate.from_template('Você é um assistente de um vendedor do mercado livre, responda a mensagem:{mensagem} dele com base nos dados fornecidos: {mensagem_final} e deixe sua resposta bem robusta dando a resposta para a pergunta, mas se possivel complementaar a respostas caso tenha dados extras para deixaar a resposta mais colorida com mais dados.')
    chain= prompt | model | StrOutputParser()
    print('informação final:', informacao_final)
    informacao_final += f'\ndata de hoje: {datetime.now()}'
    resposta_final=chain.invoke({'mensagem_final':informacao_final, 'mensagem':mensagem})
    print("resposta final: ", resposta_final)
    return jsonify({'resposta_final':resposta_final})


def chat_novai_manager_pilot(pergunta : str, user_id : int):
    model = ChatOpenAI(model='gpt-4o-mini')
    prompt = ChatPromptTemplate.from_template('''
    dada a pergunta do vendedor do mercado livre,
    categorize a pergunta,
    simples: pode ser respondida de forma simples sem agregar dados do vendedor ou da api publica do mercado lire( normalmenlte prerguntas sobre regras do mercado livre, recomendações de como vender, ou ate mesmo duvidas sobre outros sistemas, etc...).
    dados_vendedor: resposta que precise pegar as informações do vendedor para ser respondidas ou que pelo menos ajude a responder o vendedor com seus dados atualizados;                 
    api publica do mercado livre: pergunta que precise de dados que nao sao do vendedor e é possível pegar pela api publica do mercado livre;
    Pergunta:{pergunta}
    analise a pergunta, pense em como ela poderia ser respondida, e conclua se seria importante mais infomrações para responde-la de forma personalizada e no final categorize.
    responda no maximo em 10 linhas
    ''')
    class EncaminharNeuronio(BaseModel):
        '''Categorize a pergunta'''
        resp: str = Field(description='Responda exatamente com: "api publica mercado livre", "dados_vendedor" ou "simples".')
    return_final = None
    def route(input):
        print("Primeiro neuronio: ",input.resp)
        nonlocal return_final
        if input.resp=='simples':
            chain_temp = model | StrOutputParser()
            resposta=chain_temp.invoke(f'Você é um assitente de vendedores do mercado livre responda apenas perguntas sobre esse assunto e se nao souber responde que nao sabe, mas nao de informação errada, pergunta: {pergunta}')
            print("resposta:",resposta)
            return_final = resposta
        elif input.resp=='dados_vendedor':

            return_final = chat_novai_manager_requisicao(pergunta,user_id)

        else:
            print("API do mercado livre resposta")
            return_final = "nao temos api do mercado livre "
    chain_TESTE = prompt | model | StrOutputParser()
    pensamento = chain_TESTE.invoke(pergunta)
    print(f'Resposta do Pilot Teste: \n{pensamento}')
    chain = model.with_structured_output(EncaminharNeuronio) | route
    chain.invoke(pensamento)
    print('return pilot:', return_final)
    return return_final

def _sender_from_author(author: str) -> str:
    """
    Converte o 'author' do seu banco para o enum do front: 'ai' | 'user'.
    Ajuste as regras conforme seus valores reais.
    """
    if not author:
        return 'user'
    a = author.lower()
    # exemplos: 'bot', 'bot|vendedor', 'ai'
    if 'bot' in a or a == 'ai':
        return 'ai'
    return 'user'

def _to_epoch_ms(dt):
    # dt é TIMESTAMPTZ; garanta que é timezone-aware
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)

def to_date_str(value_dt):
    """datetime/date -> 'YYYY-MM-DD' (string)"""
    if isinstance(value_dt, datetime):
        return value_dt.date().isoformat()
    if isinstance(value_dt, date):
        return value_dt.isoformat()
    return None

def parse_dt(value):
    """Converte str/datetime/date -> datetime (naive). Retorna None se inválido."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        s = value.strip().replace('Z', '')
        # Tenta ISO completo (com hora) e só data
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d"):
            try:
                return datetime.strptime(s[:len(fmt)], fmt)
            except ValueError:
                continue
        # fallback fromisoformat
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return None
    return None

@socketio.on('mudar_data')
def atualizar_dados(data):
    try:
        token = request.cookies.get("__Host-token")
        if not token:
            socketio.emit('Sem_token',{"message":"Sem token"})
            return
        # Obtém o user_id dos parâmetros da query string
        print("Token:", token)
        try:
            decoded_token=decode_token(token)
            print(decoded_token)
            user_id=decoded_token.get("sub")
            print(user_id)
            room = f'user:{user_id}'
            exp_timestamp = decoded_token.get("exp")
            now = int(time.time())
            if exp_timestamp and exp_timestamp < now:
                socketio.emit('Sem_token',{"message":"Token expirado"})
                return
        except:
            return
        card_id  = data.get('cardId')          # 'earnings' | 'shares' | etc.
        start_in = data.get('start')           # vem string ISO do front
        end_in   = data.get('end')             # string ISO ou None
    
        # Parse base como datetime
        start_dt = parse_dt(start_in)
        end_dt   = parse_dt(end_in) if end_in else None
    
        if not start_dt:
            emit('atualizar_dados', {'error': 'Data inicial inválida'})
            return
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # pegue suas credenciais (ajuste nomes de colunas conforme seu schema)
                cur.execute("""
                    SELECT acess_token, id_ml
                    FROM contas_mercado_livre
                    WHERE usuario_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                """, (user_id,))
                cred = cur.fetchone()
                acess_token = cred['acess_token'] if cred else None
                id_ml       = cred['id_ml']       if cred else None

                # ---------------- earnings (usa timestamp) ----------------
                if card_id == 'earnings':
                    # Se não houver end, usa janela de 1 dia
                    if not end_dt:
                        end_dt = start_dt + timedelta(days=1)

                    # Opção A (intervalo fechado): BETWEEN start_dt AND end_dt
                    # Opção B (mais comum): >= start_dt AND < end_dt (exclusivo)
                    cur.execute("""
                        SELECT COALESCE(SUM(total_amount),0) AS total
                        FROM pedidos_resumo
                        WHERE usuario_id_pedidos_resumo = %s
                          AND date_created >= %s::timestamp
                          AND date_created <  %s::timestamp
                    """, (user_id, start_dt, end_dt))

                    row = cur.fetchone()
                    total_amount = float(row['total']) if row and row['total'] is not None else 0.0
                    emit('atualizar_dados', {'total_amount': total_amount})
                    return

                # ---------------- shares (usa apenas data) ----------------
                if card_id == 'shares':
                    if not acess_token or not id_ml:
                        emit('atualizar_dados', {'error': 'Credenciais ML ausentes'})
                        return

                    date_from = to_date_str(start_dt)
                    if end_dt:
                        date_to = to_date_str(end_dt)
                    else:
                        # janela de 1 dia
                        date_to = (start_dt + timedelta(days=1)).date().isoformat()

                    headers = {"Authorization": f"Bearer {acess_token}"}
                    url = (
                        f"https://api.mercadolibre.com/users/{id_ml}/items_visits"
                        f"?date_from={date_from}&date_to={date_to}"
                    )
                    try:
                        resp = requests.get(url, headers=headers, timeout=20)
                        if resp.ok:
                            payload = resp.json()
                            total_visits = payload.get('total_visits') if isinstance(payload, dict) else None
                            emit('atualizar_dados', {'visualizacoes_hoje': total_visits})
                        else:
                            app.logger.warning('Falha ML: %s %s', resp.status_code, resp.text)
                            emit('atualizar_dados', {'error': 'Falha ML'})
                    except requests.exceptions.RequestException as exc:
                        app.logger.exception('Erro de rede ML: %s', exc)
                        emit('atualizar_dados', {'error': 'Erro de rede ML'})
                    return

                emit('atualizar_dados', {'info': f'cardId não tratado: {card_id}'})
    except Exception as exc:
        app.logger.exception('Erro em mudar_data: %s', exc)
        emit('atualizar_dados', {'error': 'Erro interno'})



ALLOWED_ORDER = {"default", "updated_desc", "due_date_asc"}
ALLOWED_STATUS = {"opened", "closed", "pendent-novai"}

def _parse_auth_or_400() -> int:
    """Extrai e valida o token do header Authorization e retorna user_id (sub)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise ValueError("Cabeçalho Authorization ausente")

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header
    try:
        decoded = decode_token(token)
    except ExpiredSignatureError:
        # Propague como ValueError para ser tratado no endpoint
        raise ValueError("Token expirado")
    except InvalidTokenError:
        raise ValueError("Token inválido")
    except Exception as exc:
        raise ValueError(f"Falha ao decodificar token: {exc}")

    user_id = decoded.get("sub") if decoded else None
    if not user_id:
        raise ValueError("Usuário não encontrado no token (sub ausente)")
    return int(user_id)


def _get_seller_id_ml(user_id: int) -> Optional[int]:
    """
    Busca o id_ml mais recente da conta Mercado Livre do usuário.
    Se não existir, retorna None.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id_ml
                    FROM contas_mercado_livre
                    WHERE usuario_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                # row pode ser RealDictRow ou tupla; trate ambos:
                return row["id_ml"] if isinstance(row, dict) else row[0]
    except Exception:
        # Não derrube a requisição se essa consulta falhar; apenas não filtra por vendedor_id
        return None


def _serialize_claim(row: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row)
    for k in ("date_created", "last_updated", "due_date", "date_resolution"):
        if d.get(k) is not None:
            d[k] = d[k].isoformat()
    return d


def _status_order_case() -> str:
    # Prioridade: opened (0) < pendent-novai (1) < closed (2) < demais (3)
    return (
        "CASE "
        "WHEN status = 'opened' THEN 0 "
        "WHEN status = 'pendent-novai' THEN 1 "
        "WHEN status = 'closed' THEN 2 "
        "ELSE 3 END"
    )


def _safe_int(param: str, default: int, minv: int, maxv: int) -> int:
    try:
        v = int(request.args.get(param, default))
        return max(minv, min(maxv, v))
    except Exception:
        return default

@app.route("/claims", methods=["GET"])
def list_claims():
    # 1) Autenticação
    try:
        user_id = _parse_auth_or_400()
    except ValueError as e:
        # mensagens iguais ao seu padrão
        msg = str(e)
        if "ausente" in msg:
            return jsonify({"error": msg}), 401
        if "expirado" in msg:
            return jsonify({"error": msg}), 401
        if "inválido" in msg:
            return jsonify({"error": msg}), 401
        return jsonify({"error": msg}), 400

    # 2) Parâmetros
    status = request.args.get("status")
    if status and status not in ALLOWED_STATUS:
        return jsonify({"error": f"status inválido. Use um de {sorted(ALLOWED_STATUS)}"}), 400

    q = (request.args.get("q") or "").strip()
    page = _safe_int("page", default=1, minv=1, maxv=10_000)
    limit = _safe_int("limit", default=50, minv=1, maxv=200)
    offset = (page - 1) * limit

    order = request.args.get("order", "default")
    if order not in ALLOWED_ORDER:
        order = "default"

    # 3) Filtro de segurança (usuario_id OU vendedor_id)
    seller_id_ml = _get_seller_id_ml(user_id)
    # construímos (usuario_id_reclamacoes = %s OR vendedor_id = %s) quando tivermos ambos
    sec_filter, sec_params = [], []
    if seller_id_ml is not None:
        sec_filter.append("(usuario_id_reclamacoes = %s OR vendedor_id = %s)")
        sec_params.extend([user_id, seller_id_ml])
    else:
        sec_filter.append("usuario_id_reclamacoes = %s")
        sec_params.append(user_id)

    # 4) Where dinâmico
    where, params = [], []
    where.extend(sec_filter)
    params.extend(sec_params)

    if status:
        where.append("status = %s")
        params.append(status)

    if q:
        # Se você tiver EXTENSION unaccent, pode trocar para unaccent(title) ILIKE unaccent(%s)
        where.append(
            "("
            "title ILIKE %s OR "
            "problem ILIKE %s OR "
            "description ILIKE %s OR "
            "name_reason ILIKE %s"
            ")"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like])

    where_sql = " WHERE " + " AND ".join(where)

    # 5) Ordenação
    if order == "updated_desc":
        order_sql = " ORDER BY last_updated DESC NULLS LAST"
    elif order == "due_date_asc":
        order_sql = " ORDER BY due_date ASC NULLS LAST"
    else:
        order_sql = f" ORDER BY {_status_order_case()}, due_date ASC NULLS LAST, last_updated DESC NULLS LAST"

    sql = (
        "SELECT * FROM reclamacoes"
        f"{where_sql}"
        f"{order_sql}"
        " LIMIT %s OFFSET %s"
    )
    params_all = params + [limit, offset]

    count_sql = "SELECT COUNT(*) AS total FROM reclamacoes" + where_sql

    # 6) Execução
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(count_sql, params)
                total = cur.fetchone()["total"]

                cur.execute(sql, params_all)
                rows = cur.fetchall() or []
    except Exception as exc:
        return jsonify({"error": f"Erro ao consultar banco de dados: {exc}"}), 500

    claims = [_serialize_claim(r) for r in rows]

    resp = jsonify({"claims": claims, "page": page, "limit": limit, "total": total})
    # Útil pro front paginar sem parsear JSON
    resp.headers["X-Total-Count"] = str(total)
    return resp

@app.route("/claims/counters", methods=["GET"])
def claim_counters():
    try:
        user_id = _parse_auth_or_400()
    except ValueError as e:
        msg = str(e)
        if "ausente" in msg:
            return jsonify({"error": msg}), 401
        if "expirado" in msg:
            return jsonify({"error": msg}), 401
        if "inválido" in msg:
            return jsonify({"error": msg}), 401
        return jsonify({"error": msg}), 400

    seller_id_ml = _get_seller_id_ml(user_id)

    where = []
    params: List[Any] = []

    if seller_id_ml is not None:
        where.append("(usuario_id_reclamacoes = %s OR vendedor_id = %s)")
        params.extend([user_id, seller_id_ml])
    else:
        where.append("usuario_id_reclamacoes = %s")
        params.append(user_id)

    where_sql = " WHERE " + " AND ".join(where)

    sql = (
        "SELECT "
        "  COUNT(*) FILTER (WHERE status = 'opened') AS opened, "
        "  COUNT(*) FILTER (WHERE status = 'closed') AS closed, "
        "  COUNT(*) FILTER (WHERE status = 'pendent-novai') AS pendent_novai, "
        "  COUNT(*) AS total "
        "FROM reclamacoes"
        f"{where_sql}"
    )

    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                row = cur.fetchone() or {"opened": 0, "closed": 0, "pendent_novai": 0, "total": 0}
    except Exception as exc:
        return jsonify({"error": f"Erro ao consultar banco de dados: {exc}"}), 500

    return jsonify({
        "opened": row.get("opened", 0) or 0,
        "closed": row.get("closed", 0) or 0,
        "pendent_novai": row.get("pendent_novai", 0) or 0,
        "total": row.get("total", 0) or 0
    })

@app.route("/claims/<int:claim_id>", methods=["GET"])
def claim_detail(claim_id: int):
    try:
        user_id = _parse_auth_or_400()
    except ValueError as e:
        msg = str(e)
        if "ausente" in msg:
            return jsonify({"error": msg}), 401
        if "expirado" in msg:
            return jsonify({"error": msg}), 401
        if "inválido" in msg:
            return jsonify({"error": msg}), 401
        return jsonify({"error": msg}), 400

    seller_id_ml = _get_seller_id_ml(user_id)

    where = ["claim_id = %s"]
    params: List[Any] = [claim_id]

    if seller_id_ml is not None:
        where.append("(usuario_id_reclamacoes = %s OR vendedor_id = %s)")
        params.extend([user_id, seller_id_ml])
    else:
        where.append("usuario_id_reclamacoes = %s")
        params.append(user_id)

    where_sql = " WHERE " + " AND ".join(where)
    sql = "SELECT * FROM reclamacoes" + where_sql + " LIMIT 1"

    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
    except Exception as exc:
        return jsonify({"error": f"Erro ao consultar banco de dados: {exc}"}), 500

    if not row:
        return jsonify({"error": "claim_not_found"}), 404

    return jsonify({"claim": _serialize_claim(row)})


@app.route('/get_dados_gerais', methods=['GET'])
def get_dados_gerais():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Cabeçalho Authorization ausente"}), 401

    token = auth_header.split(" ")[1] if " " in auth_header else auth_header

    try:
        decoded_token = decode_token(token)
    except ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as exc:
        return jsonify({"error": f"Falha ao decodificar token: {exc}"}), 400

    user_id = decoded_token.get("sub") if decoded_token else None
    if not user_id:
        return jsonify({"error": "Usuário não encontrado no token"}), 400

    total_amount_today = 0.0
    access_token = None
    id_mercado_livre = None
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT nickname,email FROM dados_vendedor WHERE usuario_id_dados_vendedor=%s", (user_id,))
                dados_vendedor=cur.fetchone()
                if not dados_vendedor:
                    nickname,email=None,None
                else:
                    nickname=dados_vendedor['nickname']
                    email=dados_vendedor['email']
                cur.execute(
                    """
                    SELECT acess_token, id_ml
                    FROM contas_mercado_livre
                    WHERE usuario_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id,),
                )
                access_data = cur.fetchone()
                if access_data:
                    access_token = access_data.get('acess_token')
                    id_mercado_livre = access_data.get('id_ml')

                cur.execute(
                    """
                    SELECT COALESCE(SUM(total_amount), 0) AS total
                    FROM pedidos_resumo
                    WHERE date_created >= CURRENT_DATE
                      AND date_created < CURRENT_DATE + INTERVAL '1 day'
                      AND usuario_id_pedidos_resumo = %s
                    """,
                    (user_id,),
                )
                total_row = cur.fetchone()
                cur.execute(
                    """
                    SELECT SUM(am.cost) AS custo FROM anuncios_metricas_diarias am JOIN anuncios a ON a.usuario_id_anuncios=am.usuario_id_anuncios_metricas_diarias
                    WHERE a.status=%s AND a.usuario_id_anuncios = %s
                    AND am.usuario_id_anuncios_metricas_diarias = %s AND date >= CURRENT_DATE AND date < CURRENT_DATE + INTERVAL '1 days'
                    """,
                    ('active',user_id,user_id,),
                )
                custo_dict=cur.fetchone()
                custo=custo_dict['custo']
                if total_row and total_row.get('total') is not None:
                    total_amount_today = float(total_row['total'])
    except Exception as exc:
        return jsonify({"error": f"Erro ao consultar banco de dados: {exc}"}), 500

    visualizacoes_hoje = 0
    if access_token and id_mercado_livre:
        today = date.today()
        date_from = today.strftime("%Y-%m-%d")
        date_to   = (today + timedelta(days=1)).strftime("%Y-%m-%d")
        headers = {"Authorization": f"Bearer {access_token}"}
        url = (
            f"https://api.mercadolibre.com/users/{id_mercado_livre}/items_visits"
            f"?date_from={date_from}&date_to={date_to}"
        )

        try:
            response = requests.get(url, headers=headers, timeout=20)
            if response.ok:
                payload = response.json()
                print(payload)
                if isinstance(payload, dict):
                    visualizacoes_hoje=payload.get('total_visits')
            else:
                app.logger.warning(
                    'Falha ao buscar visitas no Mercado Livre: %s %s',
                    response.status_code,
                    response.text,
                )
        except requests.exceptions.RequestException as exc:
            app.logger.exception('Erro na requisição de visitas do Mercado Livre: %s', exc)

    payload = {
        'total_amount': total_amount_today,
        'visualizacoes_hoje': visualizacoes_hoje,
        'custo':custo,
        'nickname':nickname,
        'email':email,
    }

    socketio.emit('atualizar_dados', payload)
    return jsonify(payload)
        


@app.route('/get_conversation', methods=['GET'])
def get_conversation():
    print('entrou no get_conversation')
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Cabeçalho Authorization ausente"}), 401
    token = auth_header.split(" ")[1] if " " in auth_header else auth_header
    print("token: ",token)
    try:
        decoded_token=decode_token(token)
        print(decoded_token)
        user_id=decoded_token.get("sub")
        print(user_id)
        exp_timestamp = decoded_token.get("exp")
        now = int(time.time())
        if exp_timestamp and exp_timestamp < now:
            return jsonify({"error": "Token expirado"}), 333
    except:
        return
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT mensagem, id_conversa, data_envio, author FROM history_messages WHERE usuario_id_history=%s",(user_id,))
        rows=cur.fetchall()
    if not rows:
        return []
    messages=[]
    for r in rows:
        messages.append({
        "id": _to_epoch_ms(r["data_envio"]),
        "text": r['mensagem'],
        "sender":r['author'],
        "conversa_id":r['id_conversa'],
        })
    return jsonify({
        "messages": messages
    }), 200

def _row_to_message(author: str, content: str) -> BaseMessage:
    a = (author or "").lower()
    if a == "user":
        return HumanMessage(content=content)
    elif a == "ai":
        return AIMessage(content=content)
    else:
        return SystemMessage(content=content)

class Simplificador(BaseModel):
    """Cria a URL necessária para satisfazer a pergunta feita pelo vendedor."""
    url: str = Field(
        description="Retorne APENAS a URL completa da requisição HTTP (começando com https://api.mercadolibre.com/)."
    )

def categorias_mais_vendidas_concorrentes(
    user_id: int,
    message: str,
    site: str = "MLB",
) -> str:
    """
    Dado o texto do vendedor (message), retorna APENAS a URL para consultar:
      - /sites/{site}/search (ranking por categoria/termo)
      - /highlights/{site}/category/{CATEGORY_ID}
      - /trends/{site}/{CATEGORY_ID}

    Sem few-shot: usa um prompt único com regras + exemplos + categorias.
    """
    try:
        now = datetime.utcnow()
        with get_db_connection() as conn, conn.cursor() as cur:
                    cur.execute("""
                        SELECT acess_token,expiracao_token, refresh_token
                        FROM contas_mercado_livre
                        WHERE usuario_id = %s
                    """, (user_id,))
                    row = cur.fetchone()
                    access_token = row.get("acess_token")
                    if row and row.get("expiracao_token") and now > row["expiracao_token"]:
                        app.logger.info("Token expirado, renovando...")
                        dados = renovar_access_token(row["refresh_token"])
                        access_token = dados["access_token"]
                        cur.execute("""
                            UPDATE contas_mercado_livre
                            SET acess_token=%s,
                                refresh_token=%s,
                                expiracao_token=%s
                            WHERE usuario_id=%s
                        """, (dados["access_token"], dados["novo_refresh_token"],
                            dados["nova_expiracao"], user_id))
                        conn.commit()
        
        # 1) Instancia o modelo se não veio de fora
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    
        # 2) Catálogo de endpoints e exemplos (usando o parâmetro `site`)
        exemplos: List[Dict[str, Any]] = [
            {
                "EndPoint": f"https://api.mercadolibre.com/sites/{site}/search",
                "Exemplo de uso": f"/sites/{site}/search?category={{CATEGORY_ID}}&sort=sold_quantity_desc&limit=50",
                "Mais exemplos": [
                    f"/sites/{site}/search?q={{QUERY}}&sort=sold_quantity_desc&limit=50",
                    f"/sites/{site}/search?category={{CATEGORY_ID}}&sort=sold_quantity_desc&shipping=free&limit=50",
                    f"/sites/{site}/search?category={{CATEGORY_ID}}&sort=sold_quantity_desc&condition=new&limit=50",
                    f"/sites/{site}/search?category={{CATEGORY_ID}}&sort=sold_quantity_desc&price={{MIN}}-{{MAX}}&limit=50",
                    f"/sites/{site}/search?q={{QUERY}}&category={{CATEGORY_ID}}&sort=sold_quantity_desc&limit=50",
                    f"/sites/{site}/search?category={{CATEGORY_ID}}&sort=sold_quantity_desc&limit=50&offset={{0|50|100}}"
                ],
                "Pra quê serve": (
                    "Pegar ranking de itens (sold_quantity, price, seller.id, official_store_id etc.) "
                    "e montar um Top N de concorrentes por categoria/termo."
                ),
                "Observações": [
                    "sold_quantity é acumulado (não é janela de 30 dias).",
                    "Use paginação (limit/offset) para cobrir mais itens.",
                    "Filtre com available_filters (shipping, condition, price...).",
                    "Requer OAuth em muitos ambientes (401/403 sem token)."
                ]
            },
            {
                "EndPoint": f"https://api.mercadolibre.com/highlights/{site}/category/{{CATEGORY_ID}}",
                "Exemplo de uso": f"/highlights/{site}/category/MLB1055",
                "Pra quê serve": "Lista oficial de 'Mais vendidos' por categoria (ótimo para validar líderes reais e cruzar com SERP).",
                "Observações": [
                    "Retorna uma lista curta/curada. Combine com /sites/.../search para cobertura ampla."
                ]
            },
            {
                "EndPoint": f"https://api.mercadolibre.com/trends/{site}/{{CATEGORY_ID}}",
                "Exemplo de uso": f"/trends/{site}/MLB1055",
                "Pra quê serve": "Termos/consultas em alta na categoria para priorizar palavras-chave, anúncios e estoque.",
                "Observações": [
                    "Use junto com a SERP para estimar oportunidade e acompanhar sazonalidade."
                ]
            }
        ]
    
        # 3) Categorias (pode trocar por cache no seu Postgres)
        url_info_categories = f"https://api.mercadolibre.com/sites/{site}/categories"
        headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
        try:
            r = requests.get(url_info_categories, headers=headers, timeout=20)
            # compacta para id + name (suficiente para o LLM mapear nome ↔ id das raízes)
            categorias_compactas = r.json()
            print("categorias:", categorias_compactas)
        except Exception:
            categorias_compactas = []
    
      # 4) Regras e prompt único (sem few-shot)
        regras = (
            "Você é um gerador de URL para a API do Mercado Livre.\n"
            "- Site: {site}\n"
            "- Escolha SOMENTE UM endpoint entre:\n"
            "  (a) /sites/{site}/search\n"
            "  (b) /highlights/{site}/category/{{CATEGORY_ID}}\n"
            "  (c) /trends/{site}/{{CATEGORY_ID}}\n"
            "- Se o pedido for por CATEGORIA, use o CATEGORY_ID correto (veja lista de categorias abaixo).\n"
            "- Se for por TERMO (palavra-chave), use q={{QUERY}}.\n"
            "- Para ranking: inclua sort=sold_quantity_desc e limit=50.\n"
            "- Se citar frete grátis, inclua shipping=free.\n"
            "- Se citar condição (novo/usado), use condition=new ou condition=used.\n"
            "- Se citar faixa de preço, use price=MIN-MAX (ex.: price=100-500).\n"
            "- Se citar paginação, inclua offset (múltiplos de 50).\n"
            "- Responda APENAS com JSON válido no formato: {{\"url\": \"<URL_COMPLETA>\"}}.\n"
        )
        
        prompt_tmpl = PromptTemplate(
            input_variables=["input", "exemplos", "categorias", "regras", "site"],
            template=(
                "REGRAS:\n{regras}\n\n"
                "ENDPOINTS DISPONÍVEIS (exemplos e observações):\n{exemplos}\n\n"
                "CATEGORIAS CONHECIDAS (id↔nome, raízes):\n{categorias}\n\n"
                "PERGUNTA:\n{input}\n\n"
                "SAÍDA ESPERADA (APENAS JSON): {{\"url\": \"...\"}}\n"
            ),
        )
        
        # 5) Executa o chain com structured output
        chain = prompt_tmpl | llm.with_structured_output(Simplificador)
        out: Simplificador = chain.invoke({
            "input": message,
            "exemplos": json.dumps(exemplos, ensure_ascii=False),
            "categorias": json.dumps(categorias_compactas, ensure_ascii=False),
            "regras": regras,
            "site": site,  # <<< agora o template usa {site}
        })
        if out:
            print("url retornada:",out.url)
        url = (out.url or "").strip() if out else ""
        headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
        
        if not url:
            raise ValueError("Modelo não retornou uma URL válida.")
        resposta_json= requests.get(url, headers=headers, timeout=20)
        resposta_final = {"url":url,"dados_retornado_url":resposta_json.json(),"Categoria_id_e_nomes":categorias_compactas}
        # 6) Fallback: se vier vazio, tenta construir por termo (q=)
        if not url:
            query = quote(message.strip()) if message.strip() else "mais%20vendidos"
            url = f"https://api.mercadolibre.com/sites/{site}/search?q={query}&sort=sold_quantity_desc&limit=50"
    
        return resposta_final
    except Exception as e:
        print(f"Erro ao pegar informações extras sobre o concorrente\nErro:{str(e)}")

def itens_detalhados(itens_id_json, access_token, tipo):
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    list_items=[]
    imagens=[]
    if tipo =='categoria':
        for n, i in enumarete(itens_id_json):
            itens_id_json=i.get(n)
            content = itens_id_json.get("content")
            for j in content:
                id_item = j.get("id")
                url = f"https://api.mercadolibre.com/items/{id_item}"
                response=requests.get(url, headers=headers)
                result=response.json()
                pictures=result.get("pictures")
                url_descricao = f"https://api.mercadolibre.com/items/{id_item}/description"
                response_descricao = requests.get(url_descricao, headers=headers)
                descricao=response_descricao.get('plain_text')
                for m in pictures:
                    imagens.append(m.get("url"))
                list_items.append({"name_category":list(i.keys())[0],"title":result.get("title"),"seller_id":result.get("seller_id"),"price":result.get("price"),"base_price":result.get("base_price"),"original_price":result.get("original_price"), "list_type_id":result.get("listing_type_id"), "images":imagens,"descricao":descricao})
        return list_items

def ranking_item_id(item_id, access_token):
    #ver a posicao de um item no ranking de mais vendidos, atualiza periodicamente#
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    url=f"https://api.mercadolibre.com/highlights/MLB/product/{item_id}"
    resposta=response.get(url, headers=headers)
    resposta_final=resposta.json()
    
    
def trands_brasil(access_token):
    url="https://api.mercadolibre.com/trends/MLB"
    

def mais_vendidos_por_categoria(categorias_compactas, access_token):
    reposta_final=[]
    for n, i in enumarete(categorias_compactas):
        category_id = i.get("id")
        category_name = i.get("name")
        url_por_categoria=f"https://api.mercadolibre.com/highlights/MLB/category/{category_id}"
        resposta = requests.get(url_por_categoria, headers=headers)
        resposta_final.append({f"name":category_name,n:resposta.json()})
    return resposta_final

def get_info():
    #Pega os itens mais vendidos divididos por categoria, atualiza periodicamente#
    url_info_categories = f"https://api.mercadolibre.com/sites/{site}/categories"
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    try:
        r = requests.get(url_info_categories, headers=headers, timeout=20)
        # compacta para id + name (suficiente para o LLM mapear nome ↔ id das raízes)
        categorias_compactas = r.json()
        print("categorias:", categorias_compactas)
    except Exception:
        categorias_compactas = []
    resultado_mais_vendidos=mais_vendidos_por_categoria(categorias_compactas, access_token)
    itens_detalhes_categoria=itens_detalhados(resultado_mais_vendidos, access_token, 'categoria')
    resultado_mais_vendidos_por_termo_detalhado = itens_mais_vendidos(termo, access_token)
    itens_detalhes_termo=itens_detalhados(resultado_mais_vendido_por_termos, access_token,'termo')
    
    
    


def carregar_historico_conversa(conexao, conversa_id: str, usuario_id: int, limit: int = 6) -> list[BaseMessage]:
    """
    Busca as últimas `limit` mensagens dessa conversa/usuário e retorna em ordem cronológica
    como objetos HumanMessage/AIMessage/SystemMessage.
    - Compatível com colunas 'mensagem' OU 'mesagem' (se houver typo).
    - Tenta ordenar por data_envio; se a coluna não existir, faz fallback sem ORDER BY.
    """
    with conexao.cursor() as cur:
        try:
            cur.execute("""
                SELECT author, mensagem AS conteudo
                FROM history_messages
                WHERE id_conversa = %s AND usuario_id_history = %s
                ORDER BY data_envio DESC
                LIMIT %s
            """, (conversa_id, usuario_id, limit))
            rows = cur.fetchall()
        except Exception:
            # Fallback caso não exista data_envio
            cur.execute("""
                SELECT author, mensagem AS conteudo
                FROM history_messages
                WHERE id_conversa = %s AND usuario_id_history = %s
                LIMIT %s
            """, (conversa_id, usuario_id, limit))
            rows = cur.fetchall()

    msgs = [_row_to_message(r["author"], r["conteudo"]) for r in rows]
    return msgs

@socketio.on('chat_novai_manager')
def chat_novai_manager_requisicao(data): 
    print('entrou aqui no chat')
    token = request.cookies.get("__Host-token")
    if not token:
        socketio.emit('Sem_token',{"message":"Sem token"})
        return
    # Obtém o user_id dos parâmetros da query string
    print("Token:", token)
    try:
        decoded_token=decode_token(token)
        print(decoded_token)
        user_id=decoded_token.get("sub")
        print(user_id)
        room = f'user:{user_id}'
        exp_timestamp = decoded_token.get("exp")
        now = int(time.time())
        if exp_timestamp and exp_timestamp < now:
            socketio.emit('Sem_token',{"message":"Token expirado"})
            return
    except:
        return
    request_id = data.get("request_id")
    mensagem = data.get('message')
    id_conversa = data.get('conversa_id', '')
    date_unix = data.get('date')
    date = datetime.fromtimestamp(date_unix / 1000)
    print('token', token)
    if not user_id:
        return
    with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO history_messages (mensagem, id_conversa, usuario_id_history, data_envio, author) VALUES (%s, %s, %s, %s, %s)",(mensagem, id_conversa, user_id, date, 'user'))    
            conn.commit()
    model = ChatOpenAI(model='gpt-4o-mini',temperature=0)
    descricao_db = '''
Descrição do banco de dados PostgreSQL:

Table "campanhas": armazena informações sobre campanhas publicitárias, Utilização: acessar detalhes simples sobre estrutura da campanha - Relacionamentos : itens(N:1), campanhas_metricas_diarias(1:N), anuncios(1:N).

Table "campanhas_metricas_diarias": armazena métricas diárias de campanhas publicitárias, Utilização: acessar metricas da campanhas como cliques, prints, custo, - impression_share,top_impression_share,lost_impression_share_by_budget,lost_impression_share_by_ad_rank,acos_benchmark- Relacionamentos : campanhas(N:1).

Table "anuncios": armazena informações sobre anúncios de item ativos ou pausados, Utilização: acessar detalhes do anuncio ou nome do anuncio, status e estrutura do anuncio - Relacionamentos : itens(N:1), anuncios_metricas_diarias(1:N), campanhas(N:1).

Table "anuncios_metricas_diarias": armazena métricas diárias de anúncios, é mais completo que campanhas_metricas_diarias porque podem ter anuncios que nao estao em uma campanha, Utilização: quantidade de vendas por anuncios(pagos/product-ads) ou de forma organica ,acessar metricas do anuncio como cliques, prints, custo, organic_units_amount, organic_items_quantity etc - Relacionamentos : anuncios(N:1), itens(N:1).

Table "pedidos_resumo": todos os pedidos de clientes, Utilização: acessar pedidos de clientes, vendas, status, detalhes do pedido, itens_vendidos, categoria do item, etc. - Relacionamentos : itens(N:1), packs(N:1), reclamacoes(1:1) 

Table "itens": armazena informações e mais detalhes sobre itens disponíveis , Utilização: detalhes do item - Relacionamentos : pedidos_resumo(1:N), anuncios(1:N), anuncios_metricas_diarias(1:N), mensagens_clientes(1:N).

Table "reputacao_vendedor": armazena informações sobre a reputação, numeros de transacoes, e avaliações , Utilização: acessar reputação, transações totais,canceladas,completas, experiencia do vendedor,informações de creditos, nivel de conta, etc.

Table "dados_vendedor": armazena informações gerais e sensiveis do vendedor, Utilização: acessar dados como nome, email, telefone, endereço etc. 

Table "packs": armazena pack_id. Utilização: relacionar mensagens com pedidos. RELACIONAMENTOS : mensagens_clientes(1:N), pedidos_resumo(1:N).

Table "reclamacoes" : armazena reclamações feitas por clientes, Utilização: acessar reclamações de clientes, detalhes sobre a reclamação, status, etc. - Relacionamentos: para relacionar ela com a table pedidos_resumo, use a table packs como ponte.

Table "messages": armazena mensagens trocadas entre o vendedor e o cliente, Utilização: acessar conversas com clientes pos e pre venda - Relacionamentos: para relacionar ela com a table pedidos_resumo, use a table packs como ponte.

Table "ponte_item_promotions": armazena informações sobre itens que estão em promoções, servindo como uma ponte entre a tabela de promoções e itens, Utilização: ligar promoções com itens específicos, acessar detalhes sobre promoções de itens, status e preços promocionais, etc. - Relacionamentos: promotion(N:1), itens(N:1).

Table "promotion": armazena informações sobre promoções ativas ou pendentes ou candidatas, Utilização: acessar promoções, detalhes sobre promoções, status, tipo de promoção, benefícios, etc.

Table "marketplace_campaign_type_promotion": armazena informações especificas sobre promoções do tipo "Marketplace Campaign", Utilização: acessar promoções do tipo "Marketplace Campaign" - Relacionamentos: promotion(N:1).

Table "pre_negotiated_type_promotion_offers": armazena informações especificas sobre promoções do tipo "Pre Negotiated", Utilização: acessar promoções do tipo "Pre Negotiated" - Relacionamentos: promotion(N:1).

Table "seller_coupon_campaign_type_promotion": armazena informações especificas sobre promoções do tipo "Seller Coupon Campaign", Utilização: acessar promoções do tipo "Seller Coupon Campaign" - Relacionamentos: promotion(N:1).
    
Table "volume_type_promotion": armazena informações especificas sobre promoções do tipo "Volume", Utilização: acessar promoções do tipo "Volume" - Relacionamentos: promotion(N:1).    
    '''
    guardar_mensagem=mensagem
    mensagem += '''
Você é apenas um neurônio em um cérebro. Sua função é decidir se existe alguma tabela no banco de dados que possa conter as informações necessárias para responder ou para agregar em uma futura resposta para essa pergunta.  
Se houver, diga qual/quais tabelas são. Se não houver, apenas diga que não é possível agregar dados do banco para essa pergunta.  
Seja extremamente direto.
    '''

    exemplos = [
        {
            "pergunta": "Como posso aumentar minhas vendas?",
            "pensamento": "analisando a descrição das tables, é possivel agregar essa informação atraves da table pedidos_resumo que contem informações dos pedidos e/ ou atraves da table anuncios_metricas_diarias que contem informações sobre os anuncios e suas metricas e vendas diarias"
        },
        {
            "pergunta": "Quais os itens que mais estão vendendo no Mercado Livre?",
            "pensamento": (
                "Explícito sobre o marketplace geral (concorrentes). "
                "Chamar função externa 'categorias_mais_vendidas_concorrentes' para gerar URL de SERP."
            )
        },
        {
            "pergunta": "qual a senha do mercado livre",
            "pensamento": "analisando a descrição das tables,não é possível agregar essa informação atraves de nenhuma table"
        },
        {
            "pergunta": "Qual prazo para responder uma mensagem no pós-venda?",
            "pensamento": "analisando a descricao das tables, é possivel agregar a resposta através da table 'messages', que contem as mensagens e detalhes sobre as conversas com os clientes"
        },
        {
            "pergunta":"me mande qual item que mais vendeu e a descricao dele",
            "pensamento":"analisando a descricao das tables e suas Relações, é possível agregar a resposta atraves de duas tables: 'pedidos_resumo' e 'itens'."
        },
             {
            "pergunta": "Quais os itens que mais estão vendendo?",
            "pensamento": (
                "Pergunta ambígua (não citou Mercado Livre geral nem concorrentes). "
                "Padrão = meu negócio → usar banco: pedidos_resumo, anuncios_metricas_diarias, itens."
            )
    },
    ]

    example_prompt = PromptTemplate(
        input_variables=["pergunta", "pensamento"],
        template="""Pergunta: {pergunta}
Pensamento: {pensamento}
"""
    )

    
    prompt = FewShotPromptTemplate(
    examples=exemplos,
    example_prompt=example_prompt,
    suffix=(
        "Decida entre usar tabelas internas (meu negócio) OU chamar uma função externa (concorrentes/ML geral).\n"
        "REGRAS:\n"
        "- Se mencionar explicitamente 'no Mercado Livre', 'concorrentes', 'outros vendedores', 'ranking geral', use chamar_funcao.\n"
        "- Se for ambígua ou claramente sobre o meu negócio, use usar_tabelas (padrão).\n"
        "- possibilidade = true somente quando for usar_tabelas; false quando for chamar_funcao.\n"
        "- Quando chamar_funcao, a ÚNICA função disponível é 'categorias_mais_vendidas_concorrentes'.\n"
        "Responda SOMENTE com JSON VÁLIDO, sem texto extra, sem comentários, sem crases.\n"
        "Exemplos válidos:\n"
        '{{"possibilidade": true, "acao": "usar_tabelas", "tables": ["pedidos_resumo","itens"], "funcao": null}}\n'
        '{{"possibilidade": false, "acao": "chamar_funcao", "tables": null, "funcao": "categorias_mais_vendidas_concorrentes"}}\n\n'
        "Pergunta nova: {input}\n"
        "Base de Dados (descrição das tables): {detalhes}\n"
        "Responda APENAS com os campos do JSON."
    ),
    input_variables=["input", "detalhes"]
)


    class RoteadorSlim(BaseModel):
        possibilidade: bool = Field(description="True se dá para agregar com tables internas; False se não.")
        acao: Literal["usar_tabelas", "chamar_funcao"] = Field(description="usar_tabelas ou chamar_funcao")
        tables: Optional[List[str]] = Field(default=None, description="Tabelas quando acao='usar_tabelas'")
        funcao: Optional[Literal["categorias_mais_vendidas_concorrentes"]] = Field(default=None)
    return_final = None
    def route(out: RoteadorSlim):
        nonlocal return_final
        if out.acao == "chamar_funcao" and out.funcao == "categorias_mais_vendidas_concorrentes":
            print("Entrou na parte de concorrentes")
            return_final = categorias_mais_vendidas_concorrentes(
                user_id=user_id,
                message=mensagem,
                site='MLB'
            )
        elif out.acao == "usar_tabelas":
            print("Vai pegar os dados do proprio vendedor")
            tables = out.tables or ["pedidos_resumo", "anuncios_metricas_diarias", "itens"]
            return_final = chat_novai_manager_table_verification(tables, mensagem, user_id, id_conversa)
    partial=[]
    try:

        final_prompt_text = prompt.format(input=mensagem, detalhes=descricao_db)

        # Carrega histórico (já inclui a mensagem do usuário que você inseriu antes)
        with get_db_connection() as conn_hist:
            history_msgs = carregar_historico_conversa(conn_hist, id_conversa, user_id, limit=6)
        
        # Constrói um prompt "chat" com placeholder de histórico
        decisao_prompt = ChatPromptTemplate.from_messages([
            MessagesPlaceholder("history"),
            ("human", "{final_prompt}")
        ])
        
        decisao_chain = decisao_prompt | model.with_structured_output(RoteadorSlim) | route
        
        decisao_chain.invoke({
            "history": history_msgs,
            "final_prompt": final_prompt_text
        })
        print("chegou aqui")
        print('return final:', return_final)
        #respostas = await model.abatch([{"messages": [{"role": "user", "content": json.dumps(p['dados retornados da query']),"function":'sintetize os dados em no max 10 linhas'}]} for p in return_final])
        sintese_prompt = ChatPromptTemplate.from_messages([
    ("system", 
     "Você é um assistente de um vendedor do Mercado Livre. "
     "Uma outra IA buscou informações no banco de dados referentes ao vendedor ou faz um requisição com uma url referentes aos concorrentes. Responda de forma simples, clara e completa. "
     "Estruture a resposta assim (seja maleavel e criativo, nao siga a estrutura robustamente, mude um coisa ou outra para nao ficar na mesma):"
     "1. **Título contextual** (ex.: “🟡 Lista de Produtos para Reposição no FULL”)"
     "  - Logo abaixo, coloque a data dos dados"
     "2. **Legenda ou Critérios de Classificação** (se houver categorias)."
     "3. **Tabelas principais**, separadas por categoria."
     "4. **Notas e Sugestões**"
     "  - Ações sugeridas, concluindo, informações finais(seja criativo), etc.."
     """### Estilo\n
    - Linguagem simples e direta, termos do Mercado Livre quando fizer sentido.
    - Use **títulos** (##), **listas com bullets** e **tabelas GFM** quando ajudarem.
    - Evite parágrafos longos. Máximo ~3 linhas por parágrafo.
    - Simplifique nomes longos(ex: nome de itens longos) que podem ocupar muito espaço em listas e tabelas, para uma visualização melhor da resposta.
    - Use **emoji com moderação** para chamar atenção (📈, ⚠️, ℹ️).\n"""
     "Contexto sobre a data: "
     "Sempre informe a data que foi pego os dados."
     "Data atual:{date_atual}.\n"
     "Regras: "
     "- Evite ao maximo usar ids invés de nomes para a identificação na resposta final."
     "- Se houver muitos dados, prefira **separar em várias tabelas menores por categoria** (ex.: Vermelho / Amarelo / Verde)."  
     "- Cada tabela deve ter no máximo **10 linhas**. Se houver mais, mostre as 10 primeiras e finalize com “(+X linhas ocultas)”."
     "- Use no máximo **6 colunas** por tabela; se precisar de mais, divida em várias tabelas sequenciais.\n"
     "### Falhas ou dados ausentes: "
     "- Se faltar algum dado-chave, **diga explicitamente** o que faltou e como impacta a leitura"),
    MessagesPlaceholder("history"),
    ("human", 
     "Pergunta atual:\n{mensagem}\n\n"
     "Dados retornados do banco ou da requisição da url (se houver):\n{mensagem_final}\n\n"
     "Gere a melhor resposta possível para o vendedor.")
])
        model = ChatOpenAI(model='gpt-4.1')
        sintese_chain = sintese_prompt | model | StrOutputParser()
        date = datetime.now()
        # Reaproveita o mesmo histórico carregado acima (ou recarregue, se preferir)
        inputs = {
            "history": history_msgs,
            "date_atual":date,
            "mensagem": guardar_mensagem,
            # garanta que mensagem_final seja string; se vier lista/dict, serialize:
            "mensagem_final": json.dumps(return_final, ensure_ascii=False, default=str) if not isinstance(return_final, str) else return_final
        }
        for chunk in sintese_chain.stream(inputs):
            text=chunk
            partial.append(text)
            socketio.emit("chat_token", {"text": text, "requestId": request_id}, room=room)  
    except Exception as e:
        print(f'Erro ao processar o modelo: {e}')
    finally:
        full = "".join(partial)
        socketio.emit("chat_done", {"text": full, "requestId": request_id}, room=room)
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO history_messages (mensagem, id_conversa, usuario_id_history, data_envio, author) VALUES (%s, %s, %s, %s, %s)",(full, id_conversa, user_id, date, 'ai'))
            conn.commit()


def chat_novai_manager_table_verification(tables : list,mensagem: str,user_id: int, conversa_id: str):

    model = ChatOpenAI(model='gpt-4.1', temperature=0)

    descricao_table = {
    "campanhas": """Tabela: 'campanhas'
    Descrição: Representa campanhas de publicidade criadas pelo vendedor.
    Colunas:
    - 'campanha_id': BIGINT, PRIMARY KEY
    - 'nome': TEXT
    - 'status': TEXT (valores possíveis: active, paused, archived, scheduled, pending)
    - 'strategy': TEXT (valores possíveis: profitability, visibility, increase)
    - 'budget': NUMERIC(10,2)
    - 'currency_id': TEXT
    - 'last_updated': TIMESTAMP
    - 'date_created': TIMESTAMP
    - 'usuario_id_campanhas': INTEGER, FOREIGN KEY → usuarios(id)
    - 'channel': TEXT (marketplace, mshops)
    - 'acos_target': NUMERIC(10,2)
    Relacionamentos:
    - campanhas → campanhas_metricas_diarias (1:N)
    - campanhas → anuncios (1:N)
    """,

        "anuncios": """Tabela: 'anuncios'
    Descrição: Anúncios ativos ou pausados, relacionados a campanhas e itens.
    Colunas:
    - 'id_anuncio': TEXT, PRIMARY KEY
    - 'item_id': TEXT, FOREIGN KEY → itens(item_id)
    - 'title': TEXT,
    - 'price': NUMERIC(10,2),
    - 'campanha_id': INTEGER, FOREIGN KEY → campanhas(campanha_id)
    - 'status': TEXT (valores possíveis: active, paused, hold)
    - 'has_discount': BOOLEAN
    - 'catalog_listing': BOOLEAN
    - 'logistic_type': TEXT (default, fulfillment, drop_off, cross_docking, xd_drop_off)
    - 'listing_type_id': TEXT (gold_pro (explicação: categoria de maior visibilidade e destaque, possibilidades de upgrades(videos, destaques, etc)), gold_special(explicação: categoria classica, padrao mais simples), free(nao pago))
    - 'date_created': TIMESTAMP
    - 'buy_box_winner': BOOLEAN
    - 'channel': TEXT
    - 'condition': TEXT (new, used)
    - 'current_level': TEXT (unknown,geen , yellow, red, newbie)(reputação do anuncio)
    - 'recomended': BOOLEAN (se Mercado Livre recomenda esse item para publicidade neste momento)
    - 'image_quality': TEXT (high, medium, low)
    - 'usuario_id_anuncios': INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - anuncios → anuncios_metricas_diarias (1:N)
    """,

        "campanhas_metricas_diarias": """Tabela: 'campanhas_metricas_diarias'
    Descrição: Métricas de desempenho diário das campanhas.
    Colunas:
    - 'campanha_id': INTEGER, FOREIGN KEY → campanhas(campanha_id)
    - 'nome': TEXT
    - 'clicks': INTEGER
    - 'prints': INTEGER
    - 'cost': NUMERIC(10,2)
    - 'cpc': NUMERIC(6,2)
    - 'ctr': NUMERIC(10,2) → (clicks/prints)*100
    - 'direct_amount': NUMERIC(10,2)
    - 'indirect_amount': NUMERIC(10,2)
    - 'organic_amount': NUMERIC(10,2)
    - 'direct_units_quantity': INTEGER
    - 'indirect_units_quantity': INTEGER
    - 'organic_units_quantity': INTEGER
    - 'direct_items_quantity': INTEGER
    - 'indirect_items_quantity': INTEGER
    - 'organic_items_quantity': INTEGER
    - 'advertising_items_quantity': INTEGER -- (Total de anúncios ativos na campanha)
    - 'acos': NUMERIC(10,2)
    - 'cvr': NUMERIC(10,2)
    - 'roas': NUMERIC(10,2)
    - 'sov': NUMERIC(10,2)
    - 'impression_share': NUMERIC(10,2) -- (%, de impressões que seu anúncio obteve em relação ao total possível)
    - 'top_impression_share': NUMERIC(10,2) -- (%, de impressões no topo dos resultados)
    - 'lost_impression_share_by_budget': NUMERIC(10,2) -- (%, de impressões perdidas por orçamento insuficiente)
    - 'lost_impression_share_by_ad_rank': NUMERIC(10,2) -- (%, de impressões perdidas por ranking baixo (relevância/lance))
    - 'acos_benchmark': NUMERIC(10,2) -- (ACOS médio do mercado para comparação)
    - 'date': TIMESTAMP
    - 'usuario_id_campanhas_metricas_diarias': INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - campanhas_metricas_diarias → campanhas (N:1)
    """,

        "anuncios_metricas_diarias": """Tabela: 'anuncios_metricas_diarias'
    Descrição: Métricas de desempenho diário dos anúncios.
    Colunas:
    - 'id_anuncio': TEXT, FOREIGN KEY → anuncios(id_anuncio)
    - 'item_id': TEXT, FOREIGN KEY → itens(item_id)
    - 'title': TEXT
    - 'clicks': INTEGER
    - 'prints': INTEGER
    - 'cost': NUMERIC(10,2)
    - 'cpc': NUMERIC(10,2)
    - 'direct_amount': NUMERIC(10,2)
    - 'indirect_amount': NUMERIC(10,2)
    - 'organic_amount': NUMERIC(10,2)
    - 'direct_units_quantity': INTEGER
    - 'indirect_units_quantity': INTEGER
    - 'organic_units_quantity': INTEGER
    - 'direct_items_quantity': INTEGER
    - 'indirect_items_quantity': INTEGER
    - 'organic_items_quantity': INTEGER
    - 'advertising_items_quantity': INTEGER -- (Total de anúncios ativos na campanha)
    - 'acos': NUMERIC(10,2)
    - 'sov': NUMERIC(10,2)
    - 'ctr': NUMERIC(10,2)
    - 'cvr': NUMERIC(10,2)
    - 'roas': NUMERIC(10,2)
    - 'date': TIMESTAMP
    - 'usuario_id_anuncios_metricas_diarias': INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - anuncios_metricas_diarias → anuncios (N:1)
    """,

    'pedidos_resumo': """Tabela: 'pedidos_resumo'
    Descrição: Todos os pedidos feitos por clientes.
    Colunas:
    - 'id_order': TEXT, PRIMARY KEY
    - 'date_created': TIMESTAMP
    - 'date_closed': TIMESTAMP
    - 'date_approved': TIMESTAMP
    - 'last_updated': TIMESTAMP
    - 'status': TEXT (valores possíveis: approved, in_mediation, rejected, charged_back, refunded, cancelled)
    - 'total_amount': NUMERIC(10,2)
    - 'paid_amount': NUMERIC(10,2)
    - 'shipping_cost': NUMERIC(10,2)
    - 'payment_method': TEXT (valores possíveis: credit_card, debit_card, bank_transfer, boleto, cash_on_delivery)
    - 'payment_type': TEXT (valores possíveis: regular_payment, pre_authorized_payment, deferred_payment)
    - 'installments': INTEGER
    - 'installment_amount': NUMERIC(10,2)
    - 'item_id': TEXT, FOREIGN KEY → itens(item_id)
    - 'nome_item': TEXT
    - 'item_condition': TEXT (new, used)
    - 'item_warranty': TEXT (valores possíveis: no_warranty, warranty, extended_warranty)
    - 'listing_type_id': TEXT (valores possíveis: gold_pro, gold_special, free)
    - 'category_name': TEXT
    - 'unit_price': NUMERIC(10,2)
    - 'sale_fee': BOOLEAN
    - 'quantity': INTEGER
    - 'buyer_id': TEXT, FOREIGN KEY → usuarios(id)
    - 'tags': TEXT[] (array de tags associadas ao pedido)
    - 'fullfiled': BOOLEAN (indica se o pedido foi totalmente entregue)
    - 'pack_id': TEXT, FOREIGN KEY → packs(pack_id)
    - 'usuario_id_pedidos_resumo': INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - pedidos_resumo → itens (N:1)
    - pedidos_resumo → packs (N:1)
    - pedidos_resumo → reclamacoes (1:1) através de packs
    """,
        "itens": """Tabela: 'itens'
    Descrição: Catálogo de produtos cadastrados pelo vendedor.
    Colunas:
    - 'usuario_id_item': INTEGER, FOREIGN KEY → usuarios(id)
    - 'item_id': TEXT, PRIMARY KEY
    - 'nome_item': TEXT
    - 'quantidade': INTEGER
    - 'preco': NUMERIC(9,2)
    - 'descricao': TEXT
    - 'imagem': TEXT[] (array de URLs)
    - 'preco_original': NUMERIC(9,2)
    - 'preco_base': NUMERIC(9,2)
    - 'disponivel': BOOLEAN
    - 'tipo_ad': TEXT
    - 'categoria': TEXT
    Relacionamentos:
    - itens → anuncios (1:N)
    - itens → pedidos_resumo (1:N)
    - itens → anuncios_metricas_diarias (1:N)
    - itens → mensagens_clientes (1:N)
    """,
    "reputacao_vendedor": '''Tabela: "reputacao_vendedor"
    Descrição: Armazena informações sobre a reputação do vendedor.
    Colunas:
    - "level_id": TEXT
    - "power_seller_status": TEXT 
    - "period": TEXT(EX: historic)
    - "total_transactions": INTEGER
    - "completed_transactions": INTEGER
    - "canceled_transactions": INTEGER
    - "positive_reviews": NUMERIC(3,2)
    - "neutral_reviews": NUMERIC(3,2)
    - "negative_reviews": NUMERIC(3,2)
    - "tags" : TEXT[]
    - "seller_experience": TEXT 
    - "usuario_id_reputacao_vendedor": INTEGER, FOREIGN KEY → usuarios(id)
    - "consumed_credit": NUMERIC(10,2)
    - "credit_level_id": TEXT
    - "user_type": TEXT
    ''',
    "dados_vendedor": '''Tabela: "dados_vendedor"
    Descrição: Armazena informações gerais e sensiveis do vendedor
    Colunas:
    - "id_ml": BIGINT
    - "first_name": TEXT
    - "last_name": TEXT
    - "email": TEXT
    - "identification_type": TEXT
    - "identification_number": BIGINT
    - "state": TEXT
    - "city": TEXT
    - "address": TEXT
    - "zip_code": BIGINT
    - "phone_number": BIGINT
    - "verified": BOOLEAN
    - "usuario_id_dados_vendedor": INTEGER, FOREIGN KEY → usuarios(id)
    - "nickname": TEXT
    - "registration_date": TIMESTAMP
    - "site_id": TEXT
    - "permalink": TEXT
    - "shipping_mode": TEXT[]
    - "logo": TEXT (URL da imagem)
    ''',
    "packs": '''Tabela: "packs"
    Descrição: Armazena pack_id para relacionar mensagens com pedidos.
    Colunas:
    - "pack_id": TEXT, PRIMARY KEY
    - "usuario_id_packs": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - packs → mensagens_clientes (1:N)
    - packs → pedidos_resumo (1:N)
    ''',
    "messages": '''Tabela: "messages"
    Descrição: Armazena mensagens trocadas entre o vendedor e o cliente.
    Colunas:
    - "pack_id": TEXT, FOREIGN KEY → packs(pack_id), obs: (apenas para type = 'post_sale, pode se relacionar com a table itens para pegar detalhes do item)
    - "item_id": TEXT, FOREIGN KEY → itens(item_id), obs:(apenas para type = 'pre_sale')
    - "client_name": TEXT
    - "message": TEXT
    - "date_created": TIMESTAMP
    - "author": TEXT (seller, buyer,AI)
    - "type": TEXT (post_sale, pre_sale)
    - "read": BOOLEAN
    - "is_first_message": TEXT, obs:(apenas para type = 'post_sale')
    
    - "status": TEXT (answered,active,etc), obs:(apenas para type = 'pre_sale')
    - "usuario_id_messages": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - messages → packs (N:1)
    - messages → itens (N:1)
    ''',
    "promotion": '''Tabela: "promotion"
    Descrição: Armazena informações sobre promoções ativas ou pendentes ou candidatas do vendedor.
    Colunas:
    - "id_promotion": TEXT, PRIMARY KEY
    - "name": TEXT
    - "status": TEXT (started, pending, candidate)
    - "start_date": TIMESTAMP
    - "finish_date": TIMESTAMP
    - "deadline_date": TIMESTAMP
    - "type_promotion": TEXT
    - "usuario_id_promotions": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - promotion → ponte_item_promotions (1:N)
    ''',
    "marketplace_campaign_type_promotion": '''Tabela: "marketplace_campaign_type_promotion"
    Descrição: Armazena informações de promoções do tipo "marketplace_campaign_type_promotion".
    Colunas:
    - "id_promotion": TEXT, PRIMARY KEY, FOREIGN KEY → promotion(id_promotion)
    - "type_promotioin": TEXT
    - "type_benefits": TEXT
    - "meli_percentage": NUMERIC(10,2)
    - "seller_percentage": NUMERIC(10,2)
    - "usuario_id_marketplace_campaign_type_promotion": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - marketplace_campaign_type_promotion → promotion (N:1)
    ''',
    "pre_negotiated_type_promotion_offers": '''Tabela: "pre_negotiated_type_promotion_offers"
    Descrição: Armazena informações de promoções do tipo "pre_negotiated_type_promotion_offers".
    Colunas:
    - "id_promotion": TEXT, PRIMARY KEY, FOREIGN KEY → promotion(id_promotion)
    - "type_promotion": TEXT
    - "offer_id": TEXT
    - "type_benefits": TEXT
    - "meli_percent": NUMERIC(10,2)
    - "seller_percent": NUMERIC(10,2)
    - "start_date": TIMESTAMP
    - "end_date": TIMESTAMP
    - "status": TEXT 
    - "original_price": NUMERIC(10,2)
    - "new_price": NUMERIC(10,2)
    - "usuario_id_pre_negotiated_type_promotion_offers": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - pre_negotiated_type_promotion_offers → promotion (N:1)
    ''',
    "seller_coupon_campaign_type_promotion": '''Tabela: "seller_coupon_campaign_type_promotion"
    Descrição: Armazena informações de promoções do tipo "seller_coupon_campaign_type_promotion".
    Colunas:
    - "id_promotion": TEXT, PRIMARY KEY, FOREIGN KEY → promotion(id_promotion)
    - "type_promotion": TEXT
    - "sub_type": TEXT
    - "fixed_amount": NUMERIC(10,2)
    - "fixed_percentage": NUMERIC(10,2)
    - "min_purchase_amount": INTEGER 
    - "max_purchase_amount": INTEGER
    - "redeems_per_user": INTEGER
    - "budget": NUMERIC(10,2)
    - "remaining_budget": NUMERIC(10,2)
    - "coupon_code": TEXT
    - "used_coupons": INTEGER
    - "usuario_id_seller_coupon_campaign_type_promotion": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - seller_coupon_campaign_type_promotion → promotion (N:1)
    ''',
    "volume_type_promotion": '''Tabela: "volume_type_promotion"
    Descrição: Armazena informações de promoções do tipo "volume_type_promotion".
    Colunas:
    - "id_promotion": TEXT, PRIMARY KEY, FOREIGN KEY → promotion(id_promotion)
    - "buy_quantity": INTEGER
    - "pay_quantity": INTEGER
    - "allow_combination": BOOLEAN
    - "sub_type": TEXT
    - "type_promotion": TEXT
    - "usuario_id_volume_type_promotion": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - volume_type_promotion → promotion (N:1)
    ''',
      "ponte_item_promotions": '''Tabela: "ponte_item_promotions"
    Descrição: Armazena informações sobre itens que estão em promoções, servindo como uma ponte entre a tabela de promoções e itens.
    Colunas:
    - "id_promotion": TEXT, FOREIGN KEY → promotion(id)
    - "item_id": TEXT, FOREIGN KEY → itens(item_id)
    - "status": TEXT (started, pending, candidate)
    - "price": NUMERIC(10,2)
    - "original_price": NUMERIC(10,2)
    - "min_discounted_price": NUMERIC(10,2)
    - "max_discounted_price": NUMERIC(10,2)
    - "suggested_discounted_price": NUMERIC(10,2)
    - "start_date": TIMESTAMP
    - "end_date": TIMESTAMP
    - "sub_type": TEXT
    - "offer_id": TEXT
    - "meli_percentage": NUMERIC(10,2)
    - "seller_percentage": NUMERIC(10,2)
    - "buy_quantity": INTEGER
    - "pay_quantity": INTEGER
    - "allow_combination": BOOLEAN
    - "fixed_amount": NUMERIC(10,2)
    - "fixed_percentage": NUMERIC(10,2)
    - "top_deal_price": NUMERIC(10,2)
    - "discount_percentage": NUMERIC(10,2)
    - "usuario_id_ponte_item_promotions": INTEGER, FOREIGN KEY → usuarios(id)
    Relacionamentos:
    - ponte_item_promotions → promotion (N:1)
    - ponte_item_promotions → itens (N:1)
    ''',
    'reclamacoes': '''Tabela: "reclamacoes"
    Descrição: Armazena informações sobre reclamações feitas pelos clientes.
    Colunas:
    - "claim_id": BIGINT, PRIMARY KEY
    - "resource_id": BIGINT
    - "status": TEXT (unicos valores: open, closed)
    - "tipo": TEXT
    - "stage": TEXT
    - "parent_id": BIGINT
    - "pack_id": TEXT
    - "reason_id": TEXT
    - "fulfilled": BOOLEAN
    - "quantity_type": TEXT
    - "site_id": TEXT
    - "date_created": TIMESTAMP (apenas a data em que a reclamação foi feita)
    - "last_updated": TIMESTAMP
    - "comprador_id": BIGINT
    - "acoes_disponiveis": TEXT[]
    - "name_reason": TEXT
    - "expected_solutions": TEXT[]
    - "problem": TEXT
    - "description": TEXT
    - "due_date": TIMESTAMP
    - "title": TEXT
    - "action_responsible": TEXT
    - "reason_resolution": TEXT
    - "date_resolution": TIMESTAMP
    - "benefited": TEXT[]
    - "resolution_closed_by": TEXT
    - "apllied_coverage": BOOLEAN
    - "usuario_id_reclamacoes": INTEGER, FOREIGN KEY → usuarios(id)
    - "pack_id": TEXT, FOREIGN KEY → packs(pack_id)
    Relacionamentos:
    - reclamacoes → usuarios (N:1)
    - reclamacoes → packs (N:1)
    - reclamacoes → pedidos_resumo (1:1) (através de packs)
    ''',
}


    descricao_tables = ''
    for table in tables:
        descricao_tables += f'{descricao_table.get(table)}\n'

    # ==== carrega histórico (janela de 6; ajuste se quiser) ====
    with get_db_connection() as conn_hist:
        history_msgs = carregar_historico_conversa(conn_hist, conversa_id, user_id, limit=6)

    # ==== prompt em formato de chat com histórico ====
    regras_sql = """
Você é um assistente especializado em PostgreSQL. Dada a descrição das tabelas e uma pergunta,
gere UMA ou no máximo 5 queries SQL puras, separadas por vírgula, que tragam os dados necessários
para que uma segunda IA faça os cálculos.

🧠 Regras obrigatórias:
- NÃO responda a pergunta diretamente.
- Postgres puro (sintaxe correta para Python/psycopg2).
- Saída = APENAS as SQLs (sem comentários/markdown/explicações).
- Use os nomes exatos de colunas/tabelas informados.
- TODA query deve filtrar por usuário (use o id {user_id}).
- Evite divisões por zero.
- Prefira prefixos/aliases nas colunas para evitar ambiguidade.
- Seja objetivo; evite retornar muitas linhas.
- Se precisar enriquecer, inclua até 2–4 queries agregadas e leves (com LIMIT quando fizer sentido).
- Queries de enriquecimento: limite até 1000 linhas (LIMIT 1000).
- Sempre que possível, agregue (SUM/COUNT/AVG/…).
- Id's sao apenas para relacionar as tables, sempre pegue os nomes para identificação de algo.

⚠️ Contexto sobre a data:
- Data de hoje = {data_atual}
- Se a pergunta não especificar data, restrinja aos últimos 30 dias.
"""

    decisao_prompt = ChatPromptTemplate.from_messages([
        ("system", regras_sql),
        MessagesPlaceholder("history"),
        ("human",
         "Pergunta do vendedor:\n{mensagem}\n\n"
         "Descrição das tabelas selecionadas:\n{descricao_tables}\n\n"
         "Gere as SQLs conforme as regras.")
    ])

    class Queries(BaseModel):
        lista: list[str] = Field(
            description=("Retorne as queries como uma lista de strings SQL puras. "
                         "Sem \\n no fim, sem vírgulas extras, sem markdown.")
        )

    dados = None

    def route(output: Queries):
        nonlocal dados
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            dados = []
            for respost in output.lista:
                try:
                    cur.execute(respost)
                    rows = cur.fetchall()
                    dados.append({
                        'query': respost,
                        'dados retornados da query': rows
                    })
                except Exception as e:
                    print(f"Erro ao executar a query {respost}: {e}")
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
    try:
        chain = decisao_prompt | model.with_structured_output(Queries) | route
    
        chain.invoke({
            "history": history_msgs,
            "mensagem": mensagem,
            "descricao_tables": descricao_tables,
            "data_atual": datetime.now(),
            "user_id": user_id
        })
    except Exception as e:
        print('erro no final:', e)

    return dados

# ===================== utilitários de cookies (mantidos, mas NÃO usados pelo proxy) =====================

def _persist_cookies():
    try:
        tmp = MozillaCookieJar(COOKIEJAR_PATH + ".tmp")
        for c in session.cookies:
            morsel = requests.cookies.create_cookie(
                name=c.name, value=c.value,
                domain=c.domain, path=c.path or "/",
                secure=c.secure, expires=c.expires
            )
            tmp.set_cookie(morsel)
        tmp.save(COOKIEJAR_PATH, ignore_discard=True, ignore_expires=True)
        os.replace(COOKIEJAR_PATH + ".tmp", COOKIEJAR_PATH)
    except Exception:
        pass

def _is_gate(resp) -> bool:
    try:
        u = (resp.url or "").lower()
        if "gz/webdevice/config" in u or "gz/account-verification" in u:
            return True
        peek = resp.content[:4096] if resp.content else b""
        if b"webdevice/config" in peek or b"account-verification" in peek:
            return True
    except Exception:
        pass
    return False

def ensure_device_cookie(go_url: str = "https://www.mercadolivre.com.br/") -> bool:
    """
    Mantido para uso futuro (NÃO chamado pelo proxy).
    Se precisar ativar no futuro, esta função abre Chromium headless,
    passa pelo gate e injeta cookies na session.
    """
    global _last_device_cookie_refresh

    now = time.time()
    if now - _last_device_cookie_refresh < COOKIE_REFRESH_COOLDOWN_S:
        return False

    if not _device_cookie_lock.acquire(blocking=False):
        return False

    try:
        from playwright.sync_api import sync_playwright

        gate_url = f"https://www.mercadolivre.com.br/gz/webdevice/config?go={quote(go_url, safe='')}&noscript=false"

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-gpu", "--disable-web-security",
            ])
            context = browser.new_context(
                user_agent=DEFAULT_OUT_HEADERS["User-Agent"],
                locale="pt-BR",
                viewport={"width": 1280, "height": 800},
            )

            page = context.new_page()
            page.goto(gate_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(2000)
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

            pw_cookies = context.cookies()
            useful = [c for c in pw_cookies if "mercadolivre.com.br" in (c.get("domain") or "")]
            ok = bool(useful)
            if ok:
                _merge_playwright_cookies_into_session(useful)
                _last_device_cookie_refresh = time.time()

            context.close()
            browser.close()
        return ok
    except Exception:
        return False
    finally:
        try:
            _device_cookie_lock.release()
        except Exception:
            pass

def _merge_playwright_cookies_into_session(pw_cookies):
    for c in pw_cookies:
        dom = c.get("domain") or ""
        if ".mercadolivre.com.br" not in dom and "mercadolivre.com.br" not in dom:
            continue
        morsel = requests.cookies.create_cookie(
            name=c["name"],
            value=c["value"],
            domain=dom if dom.startswith(".") or dom.startswith("www.") else "." + dom,
            path=c.get("path") or "/",
            secure=bool(c.get("secure")),
            expires=int(c.get("expires")) if c.get("expires") else None,
        )
        session.cookies.set_cookie(morsel)
    _persist_cookies()

# ===================== allowlist / sessão / headers =====================

ALLOWED_EXACT = {
    "api.mercadolibre.com",
}
ALLOWED_SUFFIXES = (
    ".mercadolivre.com.br",
    ".mercadolibre.com",
)

session = requests.Session()

COOKIEJAR_PATH = os.environ.get("ML_COOKIEJAR_PATH", "/tmp/ml_cookies.jar")
COOKIE_REFRESH_COOLDOWN_S = int(os.environ.get("ML_COOKIE_REFRESH_COOLDOWN_S", "900"))
_device_cookie_lock = threading.Lock()
_last_device_cookie_refresh = 0

server_cookiejar = MozillaCookieJar(COOKIEJAR_PATH)
if os.path.exists(COOKIEJAR_PATH):
    try:
        server_cookiejar.load(ignore_discard=True, ignore_expires=False)
    except Exception:
        pass
session.cookies.update(server_cookiejar)

retry = Retry(total=2, backoff_factor=0.2, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
session.mount("https://", adapter)
session.mount("http://", adapter)

DEFAULT_OUT_HEADERS = {
    "User-Agent":  ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"),
    "Accept":       "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
    "Pragma":        "no-cache",
}

def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http", "https"):
            return False
        host = (u.hostname or "").lower()
        if host in ALLOWED_EXACT:
            return True
        return any(host.endswith(suf) for suf in ALLOWED_SUFFIXES)
    except Exception:
        return False

def add_cors(resp: Response, allow_credentials=False):
    origin = request.headers.get("Origin")
    if allow_credentials and origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        vary = "Origin"
    else:
        resp.headers["Access-Control-Allow-Origin"] = origin or "*"
        vary = "Origin"

    req_method = request.headers.get("Access-Control-Request-Method")
    req_headers = request.headers.get("Access-Control-Request-Headers")
    resp.headers["Access-Control-Allow-Methods"] = req_method or "GET,HEAD,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = req_headers or (
        "Content-Type, Authorization, If-None-Match, If-Modified-Since, Range, Cache-Control, Pragma"
    )
    resp.headers["Access-Control-Expose-Headers"] = (
        "Content-Type, ETag, Cache-Control, Last-Modified, Location, Content-Range, Content-Length, "
        "X-Proxy-Final-Url, X-Proxy-Redirect-Count, X-Proxy-Gate"
    )
    resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers["Vary"] = f"{vary}, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

# ===================== rotas =====================

@app.route("/", defaults={"raw": ""}, methods=["OPTIONS"])
@app.route("/<path:raw>", methods=["OPTIONS"])
def _opts(raw):
    return add_cors(Response(status=204))

@app.route("/", defaults={"raw": ""}, methods=["GET"])
@app.route("/<path:raw>", methods=["GET"])
def proxy(raw: str):
    if not raw:
        return add_cors(Response("Target URL ausente", status=400))

    target = raw
    q = request.query_string.decode("utf-8")
    if q:
        target = f"{target}{'&' if '?' in target else '?'}{q}"

    if not is_allowed(target):
        return add_cors(Response("Host não permitido", status=400))

    method = request.method

    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization", "Content-Type", "Accept", "Accept-Language",
              "User-Agent", "Range", "If-None-Match", "If-Modified-Since", "Referer"):
        v = request.headers.get(k)
        if v:
            forward_headers[k] = v

    try:
        # SEGUE APENAS REDIRECTS HTTP (301/302). NÃO segue meta-refresh.
        r = session.request(
            method=method,
            url=target,
            headers=forward_headers,
            allow_redirects=True,
            timeout=(5, 30),
            stream=False,
        )

        final_r = r
        meta_hops = 0  # diagnóstico compatível com cabeçalho

    except requests.RequestException as e:
        return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    resp = Response(final_r.content, status=final_r.status_code)

    hop_by_hop = {
        "transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers", "upgrade"
    }
    for k, v in final_r.headers.items():
        lk = k.lower()
        if lk in hop_by_hop:
            continue
        if lk in ("content-type", "cache-control", "etag", "last-modified",
                  "content-range", "accept-ranges", "location"):
            resp.headers[k] = v

    try:
        http_hops = len(final_r.history)
        resp.headers["X-Proxy-Final-Url"] = final_r.url
        resp.headers["X-Proxy-Redirect-Count"] = str(http_hops + meta_hops)
        resp.headers["X-Proxy-Gate"] = "1" if _is_gate(final_r) else "0"
    except Exception:
        pass

    return add_cors(resp)



# 🚀 Rodar o servidor
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)