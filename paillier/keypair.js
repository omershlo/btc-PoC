const BigInteger = require('big-integer');
const utils = require('./../utils');
const moduloPow = utils.moduloPow;

function KeyPair(privateKey, publicKey, upperBound) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.upperBound = upperBound;
}

KeyPair.prototype.decrypt = function(cipher) {
    let decrypted = utils.modulo(moduloPow(cipher,this.privateKey.lambda, this.publicKey.nSquared)
        .subtract(BigInteger.one)
        .divide(this.publicKey.n)
        .multiply(this.privateKey.preCalculatedDenominator)
        ,this.publicKey.n);

    // if (this.upperBound !== null &&
    //     decrypted.compareTo(this.upperBound) > 0) {
    //    return decrypted.subtract(this.publicKey.n);
    // }

    return decrypted;
};

module.exports = KeyPair;