const BigInteger = require('big-integer');
const utils = require('./../utils');
const PrivateKey = require('./private-key');
const PublicKey = require('./public-key');
const KeyPair = require('./keypair');
const moduloPow = utils.moduloPow;

function KeyPairBuilder(bits = 1026, upperBound = null) {
  this.bits = bits;
  this.maximumRandom = new BigInteger(2).pow(this.bits).subtract(BigInteger.one);
  this.upperBound = upperBound;
}

KeyPairBuilder.prototype._calculateL = function(u, n) {
  return u.subtract(BigInteger.one).divide(n);
};

KeyPairBuilder.prototype.generateKeyPair = function () {
  const length = this.bits / 2;
  const maxProbablePrime = new BigInteger(2).pow(length).subtract(BigInteger.one);

  let p, q;

  p = utils.generateProbablePrime(maxProbablePrime);
  q = utils.generateProbablePrime(maxProbablePrime);

  const n = p.multiply(q);

  const nSquared = n.square();

  const pMinusOne = p.subtract(BigInteger.one);
  const qMinusOne = q.subtract(BigInteger.one);

  const lambda = BigInteger.lcm(pMinusOne, qMinusOne);

  let g, helper;

  do {
    g = utils.pickRandom(this.maximumRandom);
    helper = this._calculateL(moduloPow(g,lambda, nSquared), n);
  } while(!BigInteger.gcd(helper, n).equals(BigInteger.one));

  const publicKey = new PublicKey(n, g, this.bits);
  const privateKey = new PrivateKey(lambda, helper.modInv(n),p,q);

  return new KeyPair(privateKey, publicKey, this.upperBound);
};



module.exports = KeyPairBuilder;