const BigInteger = require('big-integer');


function PrivateKey(lambda, preCalculatedDenominator,p,q) {
  this.p = p; //omer
  this.q = q; //omer
  this.lambda = lambda;
  this.preCalculatedDenominator = preCalculatedDenominator;
  const pMinusOne = p.subtract(BigInteger.one);
  const qMinusOne = q.subtract(BigInteger.one);
  this.phi = pMinusOne.multiply(qMinusOne); //omer
}

PrivateKey.prototype.phi  = this.phi
module.exports = PrivateKey;