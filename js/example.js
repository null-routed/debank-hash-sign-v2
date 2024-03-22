const { generateSignature } = require("./signature");

const signatureData = generateSignature(
  "GET",
  "/token/balance_list",
  "user_addr=0xe8c19db00287e3536075114b2576c70773e039bd&chain=op"
);
console.log(signatureData);
