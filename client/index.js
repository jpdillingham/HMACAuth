const uuidv4 = require('uuid').v4;
const crypto = require('crypto');
const fetch = require('node-fetch');

const accessKey = '088546f2-aba0-49d0-9323-4b07bf926ab1'
const secretKey = 'pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=' // this is going to show up on that one website due the the amount of entropy

const method = 'POST';
const path = '/restricted';
const queryString = '';

const date = new Date().toISOString();
const requestId = uuidv4();

const body = JSON.stringify("Hello, World!");
const md5 = crypto.createHash('md5').update(body).digest("hex");

var signature = `${method}:${path}:${queryString}:${requestId}:${date}:${body.length}:${md5}`;

var digest = crypto.createHmac('SHA256', Buffer.from(secretKey, "base64")).update(signature, 'utf8').digest('base64');

const headers = {
  "Request-Id": requestId,
  "Date": date,
  "Content-Type": "application/json",
  "Content-Length": body.length,
  "Content-MD5": md5,
  "Authorization": `HMAC ${accessKey}:${digest}`
}

fetch('http://localhost:5000/restricted', {
  method: 'POST',
  body,
  headers
}).then(res => console.log(res.status));
