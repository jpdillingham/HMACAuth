import { v4 as uuidv4 } from 'uuid';

const accessKey = '088546f2-aba0-49d0-9323-4b07bf926ab1'
const secretKey = 'pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=' // this is going to show up on that one website due the the amount of entropy

const createDigest = ({ ...args }) => {
  return '??';
}

const callApi = () => {
  const date = new Date().toUTCString();
  const requestId = uuidv4();

  const verb = 'GET';
  const route = '/weatherForecast';

  const headers = {
    "Date": date,
    "X-Request-Id": requestId,
    "Authorization": `hmac ${accessKey}:${createDigest(verb, route, date, requestId)}`
  }

  // fetch with headers
};
