const { generateSignature } = require("./debankSignature");

const signatureData = generateSignature(
  "GET",
  "/user/config",
  "id=0xe8c19db00287e3536075114b2576c70773e039bd"
);
console.log(signatureData);
