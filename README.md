# NOVAI Proxy

Proxy de scraping do Mercado Livre com saída pela rede residencial da Decodo.

## Variáveis no Railway

Obrigatórias:

- `SP_USERNAME`: usuário mostrado em **Configuração de proxy** no Decodo.
- `SP_PASSWORD`: senha do proxy Decodo.
- `SP_ENDPOINTS`: um ou mais endpoints separados por vírgula. Para a entrada
  residencial rotativa padrão, use `gate.decodo.com:7000`.

O Railway fornece `PORT` automaticamente. Não crie nem fixe essa variável.

## Verificação

- `GET /_health`: confirma que o serviço iniciou e informa, sem revelar
  segredos, se as três configurações do Decodo foram encontradas.
- `GET /_proxy_check`: faz uma chamada real pela Decodo e retorna os dados do
  IP de saída. Retorna `decodo_not_configured` quando faltar alguma variável.

O comando de produção, o healthcheck e a política de reinício estão definidos
em `railway.json`.

## Respostas de verificação do Mercado Livre

Páginas com `account-verification` ou `/security/bot_challenge`, inclusive
quando o Mercado Livre responde com HTTP 200, são identificadas como desafios.
Se a tentativa adicional já configurada não obtiver uma resposta sem desafio,
o proxy retorna HTTP 502, `Cache-Control: no-store` e JSON:

```json
{
  "error": "upstream_challenge",
  "reason": "bot_challenge",
  "upstream_status": 200,
  "message": "O Mercado Livre retornou uma página de verificação, não os dados do anúncio."
}
```

O header `X-Proxy-Error` também contém `upstream_challenge`. A extensão deve
tratar essa resposta como dados indisponíveis, sem extrair ou inventar uma data.
Essa detecção não resolve o desafio nem garante acesso ao anúncio. A ausência
dos marcadores também não garante que o HTML contenha todos os dados procurados.

O Requests descomprime gzip, deflate e Brotli (dependência explícita). Nas
respostas com corpo, o proxy não repassa `Content-Encoding` do conteúdo já
descomprimido; o Flask calcula o tamanho do corpo que realmente será enviado.

## Testes

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Os testes usam um servidor HTTP local para verificar a descompressão real e
simular respostas do Mercado Livre, sem consumir o serviço externo ou a Decodo.
