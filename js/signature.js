const crypto = require("crypto");

function sortQueryString(queryString) {
  const params = new URLSearchParams(queryString);

  const sortedParams = Array.from(params).sort((a, b) =>
    a[0].localeCompare(b[0])
  );
  const sortedQueryString = new URLSearchParams(sortedParams).toString();

  return sortedQueryString;
}

function sha256(data) {
  return crypto.createHash("sha256").update(data);
}

function encodeText(text) {
  return new TextEncoder().encode(text);
}

function generateNonce(length = 32) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let nonce = "";
  for (let i = 0; i < length; i++) {
    nonce += characters.charAt(crypto.randomInt(0, characters.length));
  }
  return "n_" + nonce;
}

function hmacSha256(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

function generateSignature(requestMethod, path, parameters) {
  const nonce = generateNonce();
  const timestamp = Math.floor(Date.now() / 1000);
  const randStr = `debank-api\n${nonce}\n${timestamp}`;
  const randStrHash = encodeText(sha256(randStr).digest("hex"));
  const requestParams = `${requestMethod.toUpperCase()}\n${path.toLowerCase()}\n${sortQueryString(
    parameters.toLowerCase()
  )}`;
  const requestParamsHash = encodeText(sha256(requestParams).digest("hex"));

  const signature = hmacSha256(randStrHash, requestParamsHash);

  return {
    nonce,
    timestamp,
    signature,
  };
}

module.exports = { generateSignature };
