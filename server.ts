import cryptojs from 'crypto-js';
import express from 'express';

const app = express();
const PORT = 3333;
const KEY = 'chave'

app.get('/token', (req,res) => {
  // cabeçalho, onde se passa criptografia e o tipo do token
  let header: any = {
    alg: 'HS256',
    typ: 'JWT'
  }
  header = JSON.stringify(header)
  header = Buffer.from(header).toString('base64')

  // corpo do token, onde vai informações do usuarios e afins
  let payload: any = {
    token_type: 'access',
    exp: 1638400515,
    'id': 1
  }
  payload = JSON.stringify(payload)
  payload = Buffer.from(payload).toString('base64')

  // assinatura do token, criptografa o cabeçalho do token e o corpo
  let signature: any = cryptojs.HmacSHA256(`${header}.${payload}`, KEY)
  signature = JSON.stringify(signature)
  signature = Buffer.from(signature).toString('base64')

  return res.send(`${header}.${payload}.${signature}`)
});


app.get('/validation', (req,res) => {
  // pegar token do cabeçalho
  const authHeader: any = req.headers.authorization

  if (!authHeader) {
    res.status(401).send({ error: 'Token not provided' })
  }

  const [, token] = authHeader.split(' ')

  // separar token em header, payload, signature
  let [header, payload, signature] = token.split('.')

  // gerar nova signature para compara com a que veio no token, caso for diferente retornar erro
  let valid: any = cryptojs.HmacSHA256(`${header}.${payload}`, KEY)
  valid = JSON.stringify(valid)
  valid = Buffer.from(valid).toString('base64')

  if (valid != signature) {
    res.status(401).send({ error: 'Token invalid' })
  }

  // tratar o payload para retornar os dados do usuario
  payload = Buffer.from(payload, 'base64').toString('ascii')
  payload = JSON.parse(payload)
  
  return res.send(payload)
})

app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});