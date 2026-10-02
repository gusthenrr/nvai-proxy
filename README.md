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
