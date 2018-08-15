const BigInteger = require('big-integer');
const utils = require('./../utils');
const moduloPow = utils.moduloPow;

function PublicKey(n, g, bits) {
  this.n = n;
  this.nSquared = n.square();
  this.g = g;
  this.bits = bits;
  this.maximumRandom = (new BigInteger(2)).pow(this.bits).subtract(BigInteger.one);
}

PublicKey.prototype.n = this.n;
PublicKey.prototype.r = this.r;
PublicKey.prototype.encrypt = function(m,rand1) {
  //if(m<0){const m = m.add(this.n);}
  if( typeof rand1 == "undefined"){
    let r;
  
    do {
      r = utils.pickRandom(this.maximumRandom)
    } while(r.compare(this.n) >= 0);
    this.r = r;
    let messageDiscreteLog = moduloPow(this.g,m, this.nSquared);
    const randomPart = moduloPow(r,this.n, this.nSquared);
  
    return utils.modulo(messageDiscreteLog.multiply(randomPart), this.nSquared);
  }

  else{
  

    let messageDiscreteLog = moduloPow(this.g,m, this.nSquared);
    const randomPart = moduloPow(rand1,this.n, this.nSquared);
  
    return utils.modulo(messageDiscreteLog.multiply(randomPart), this.nSquared);
  }

};




module.exports = PublicKey;