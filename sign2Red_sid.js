function compareCurvePoints(p1, p2) {
  return (p1.x.fromRed().toString(16) === p2.x.fromRed().toString(16)) &&
    (p1.y.fromRed().toString(16) === p2.y.fromRed().toString(16));
}
/*#######################################################################################*/
/*#######################################################################################*/
/*###################################### Server Sign #####################################*/
/*################################################## #####################################*/
function serverSignStage1({serverCache,clientCache}) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();

  const k1 = pickRandom(Consts.q);

  const R1 = utils.ec.g.mul(k1.toString(Consts.HEX));

  const a1s = pickRandom();
  const a1s_R1_concat = a1s.toString(Consts.HEX).concat(R1.x.fromRed().toString(16)).concat(serverCache['sid']);
  const hash = crypto.createHash('sha256').update(a1s_R1_concat).digest('hex');
  const com1s = modulo(new BigInteger(hash, Consts.HEX),Consts.q).toString(Consts.HEX);


  const v = pickRandom(Consts.q.minus(1));
  const ts = utils.ec.g.mul(v.toString(Consts.HEX));

  // c = H(t,G,R1) mod (q)
  const ts_g_R1_concat = ts.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), R1.x.fromRed().toString(16)).concat(serverCache['sid']);
  const ts_g_R1_concat_hash = crypto.createHash('sha256').update(ts_g_R1_concat).digest('hex');
  const c = modulo(new BigInteger(ts_g_R1_concat_hash, Consts.HEX),Consts.q);

  // r = v -  c * k1
 // const rs = v.minus(c.multiply(k1)); 
  const rs = utils.moduloSubq(v,utils.moduloMulq(c,k1));


  //com2 = H(a2,t,r)
  const a2s= pickRandom();
  const a2s_ts_rs_concat = a2s.toString(Consts.HEX).concat(ts.x.fromRed().toString(16), rs.toString(Consts.HEX)).concat(serverCache['sid']);
  const hash2 = crypto.createHash('sha256').update(a2s_ts_rs_concat).digest('hex');
  const com2s = modulo(new BigInteger(hash2, Consts.HEX),Consts.q).toString(Consts.HEX);

  serverCache['k1'] = k1;
  serverCache['a1s'] = a1s;
  serverCache['a2s'] = a2s;
  serverCache['ts'] = ts;
  serverCache['rs'] = rs;
  serverCache['R1'] = R1;
  serverCache['com1s'] = com1s;
  serverCache['com2s'] = com2s;

  return { com1s, com2s };
}

function serverSignStage2({ tc, rc, R2 ,serverCache,clientCache}) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  // Computing c2
  serverCache['R2'] = R2;
  const tc_G_R2_concat = tc.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), R2.x.fromRed().toString(16)).concat(serverCache['sid']);
  const tc_G_R2_concat_hash = crypto.createHash('sha256').update(tc_G_R2_concat).digest('hex');
  const c2 = modulo(new BigInteger(tc_G_R2_concat_hash, Consts.HEX),Consts.q);

  // Checking that tc = G*rc+R2*c2
  const rcPoint = utils.ec.g.mul(rc.toString(Consts.HEX));
  const R2c2 = R2.mul(c2.toString(Consts.HEX));
  const tc_check = rcPoint.add(R2c2);
  if (!compareCurvePoints(tc, tc_check)) {
    throw new Error('abort');
  }

  return {
    a1s: serverCache.a1s,
    a2s: serverCache.a2s,
    ts: serverCache.ts,
    rs: serverCache.rs,
    R1: serverCache.R1,
  };
}
function serverSignStage3({c3,serverCache,clientCache,recid}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const k1 = serverCache['k1'];
  const R = serverCache['R2'].mul(k1.toString(Consts.HEX));
  const signature_r = modulo(BigInteger(R.x.fromRed().toString(16),Consts.HEX),Consts.q);
  const sTag = serverCache['keyPair'].decrypt(c3);
   //(A * B) mod C = (A mod C * B mod C) mod C 
   // Template: modulo((modulo(A,C)).multiply(modulo(B,C)),C)
  const sTagTag = modulo((k1.modInv(Consts.q)).multiply(modulo(sTag,Consts.q)),Consts.q);
  const signature_s = BigInteger.min(sTagTag,Consts.q.subtract(sTagTag));
  var recid2 = recid;
  if(sTagTag.greater(Consts.q.divide(2))){recid2 = recid^1}
  // verify: 
  const w = signature_s.modInv(Consts.q);
  const A = modulo(BigInteger(serverCache['messageTag'],Consts.HEX),Consts.q);
  const B = modulo(w,Consts.q);
  const u1 = modulo((A).multiply(B),Consts.q);
  const u2 = modulo((modulo(signature_r,Consts.q)).multiply(modulo(w,Consts.q)),Consts.q);
  //can be faster using "Shamir Trick"
  const verPoint = utils.ec.g.mul(u1.toString(Consts.HEX)).add(serverCache['Q'].mul(u2.toString(Consts.HEX)));
  const ver1 = verPoint.x.fromRed().toString(16);
  const verR = signature_r.toString(16);
  console.log("a= " +verPoint.x.fromRed().toString(16))
  console.log("b= "+signature_r.toString(16))
  return {signature_r, signature_s ,recid2,ver1,verR }; 
}
/*###################################### Client Sign #####################################*/

function clientSignStage1({serverCache,clientCache}) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  // ## 3.a ##
  const k2 = pickRandom(Consts.q);

  // ## (3.b) ##

  const R2 = utils.ec.g.mul(k2.toString(Consts.HEX));

  // ## (3.c) ##
  // ZK proof of DL
  const v2 = pickRandom(Consts.q.minus(1));
  const tc = utils.ec.g.mul(v2.toString(Consts.HEX));

  // c2 = H(t2,G,Q2) mod (q)
  const tc_G_R2_concat = tc.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), R2.x.fromRed().toString(16)).concat(clientCache['sid']);
  const tc_G_R2_concat_hash = crypto.createHash('sha256').update(tc_G_R2_concat).digest('hex');
  const c2 = modulo(new BigInteger(tc_G_R2_concat_hash, Consts.HEX),Consts.q);

  // r2 = v2 -  c2 * x2
  //const rc = v2.minus(c2.multiply(k2));
  const rc = utils.moduloSubq(v2,utils.moduloMulq(c2,k2));
  clientCache['k2'] = k2;
  clientCache['R2'] = R2;

  return { tc, rc, R2 };
}

function clientSignStage2({ a1s, R1, a2s, ts, rs, com1s, com2s ,serverCache,clientCache}) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  clientCache['R1'] = R1;

  const a1s_R1_concat = a1s.toString(Consts.HEX).concat(R1.x.fromRed().toString(16)).concat(clientCache['sid']);
  const a1s_R1_concat_hash = crypto.createHash('sha256').update(a1s_R1_concat).digest('hex');
  const com1s_check = modulo(BigInteger(a1s_R1_concat_hash, Consts.HEX),Consts.q);

  if (com1s_check.toString(Consts.HEX) !== com1s.toString(Consts.HEX)) {
    throw new Error('abort');
  }

  const a2s_ts_rs_concat = a2s.toString(Consts.HEX).concat(ts.x.fromRed().toString(16), rs.toString(Consts.HEX)).concat(clientCache['sid']);
  const a2s_ts_rs_concat_hash = crypto.createHash('sha256').update(a2s_ts_rs_concat).digest('hex');
  const com2s_check = modulo(new BigInteger(a2s_ts_rs_concat_hash, Consts.HEX),Consts.q);

  if (com2s_check.toString(Consts.HEX) !== com2s.toString(Consts.HEX)) {
    throw new Error('abort');
  }

  // compute c = H(t,G,Q1) mod (q)

  const tc_g_R1_concat = ts.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), R1.x.fromRed().toString(16)).concat(clientCache['sid']);
  const tc_g_R1_concat_hash = crypto.createHash('sha256').update(tc_g_R1_concat).digest('hex');
  const c = modulo(new BigInteger(tc_g_R1_concat_hash, Consts.HEX),Consts.q);

  // calculate t = G*r+Q1*c\
  const rsPoint = utils.ec.g.mul(rs.toString(Consts.HEX));
  const R1c = R1.mul(c.toString(Consts.HEX));
  const ts_check = rsPoint.add(R1c);

  if (!compareCurvePoints(ts, ts_check)) {
    throw new Error('t check has failed - abort');
  }

  //4(b)
  const R = R1.mul(clientCache['k2'].toString(Consts.HEX));
  const rc_x = modulo(BigInteger(R.x.fromRed().toString(16),Consts.HEX),Consts.q);
  const rho = pickRandom(Consts.q.square());
  const n = clientCache['paillierPublicKey'].n;
  const nSquare = clientCache['paillierPublicKey'].nSquared;
  //const nSquare = n.multiply(n);
    //(A * B) mod C = (A mod C * B mod C) mod C 
    // Template: modulo((modulo(A,C)).multiply(modulo(B,C)),C)
  const k2inv_mul_m_mod_q = modulo((clientCache['k2'].modInv(Consts.q)).multiply(modulo(BigInteger(clientCache['messageTag'],Consts.HEX),Consts.q)),Consts.q);
  const c1 = clientCache['paillierPublicKey'].encrypt(modulo(rho.multiply(Consts.q).add(k2inv_mul_m_mod_q),n));
  const r_mul_x2 = modulo(modulo(rc_x,Consts.q).multiply(modulo(BigInteger(clientCache['x2'],Consts.HEX),Consts.q)),Consts.q);
  const v = modulo(clientCache['k2'].modInv(Consts.q).multiply(r_mul_x2),Consts.q);
  const c2 = moduloPow(BigInteger(clientCache['ciphertext'],Consts.HEX),v,nSquare);
  const c3 = modulo((modulo(c1,nSquare)).multiply(modulo(c2,nSquare)),nSquare);
  
  // calculate recover id:
  const RxBN = BigInteger(R.x.fromRed().toString(16),16);
  const RyBN = BigInteger(R.y.fromRed().toString(16),16);
  const temp = BigInteger(2).multiply(RxBN.compare(rc_x)!==0 ? 1 : 0);
  const recid = modulo(RyBN,2).add(temp);
  return {c3,recid};
}
/*###################################### TEST Sign #####################################*/
function helper(){ 
  //const btcClient = require('./btcClient')
  var querystring = require('querystring');
  var http = require('http');
  const crypto = require('crypto');
  const BigInteger = require('big-integer');
  const EC = require('elliptic').ec;
  const Consts = require('./consts');
  const utils = require('./utils');
  const pickRandom = utils.pickRandom;
  const pickRandomInRange = utils.pickRandomInRange;
  const modulo = utils.modulo;
  const moduloPow = utils.moduloPow;
  const KeyPairBuilder = require('./paillier/keypair-builder');


  return {crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder};
}

function sign(message,sid,serverCache,clientCache ,n,g,p,q,lambda,preCalculatedDenominator){

  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  //const message  = 'test';
  //const messageTag  = crypto.createHash('sha256').update(message).digest('hex');
  const PublicKey = require('./paillier/public-key');
  const N = new BigInteger(n,16);
  const G = new BigInteger(g,16);
  const paillierPublicKey = new PublicKey(N,G,1026);
  const P = new BigInteger(p,16);
  const Q = new BigInteger(q,16);
  const Lambda = new BigInteger(lambda,16);
  const PreCalculatedDenominator = new BigInteger(preCalculatedDenominator,16);
  const PrivateKey = require('./paillier/private-key');
  const paillierPrivKey = new PrivateKey(Lambda, PreCalculatedDenominator,P,Q);
  const KeyPair = require('./paillier/keyPair');
  serverCache['keyPair'] = new KeyPair(paillierPrivKey,paillierPublicKey,0);
  clientCache['paillierPublicKey'] = paillierPublicKey;
  clientCache['messageTag'] = message
  serverCache['messageTag'] = message
   const Q1 =  serverCache['q1'];
   const Q2 =  clientCache['q2'];
   const X1 = serverCache['x1'];
   const X2 = clientCache['x2'];
  const Ckey = clientCache['ciphertext'];
  const QQ = Q1.mul(X2.toString(Consts.HEX));
  clientCache['Q'] = QQ
  serverCache['Q'] = QQ
  clientCache['sid'] = sid
  serverCache['sid'] = sid
 
while(true){
  const { com1s, com2s } = serverSignStage1({serverCache,clientCache});
  const { tc, rc, R2 } = clientSignStage1({serverCache,clientCache});
  const { a1s, a2s, ts, rs, R1 } = serverSignStage2({ tc, rc, R2 ,serverCache,clientCache });
  const {c3,recid} = clientSignStage2({ a1s, R1, a2s, ts, rs, com1s, com2s,serverCache,clientCache });
  const {signature_r, signature_s,recid2,ver1,verR } = serverSignStage3({c3,serverCache,clientCache,recid});

  if(signature_r.toString(Consts.HEX).length==64 && signature_s.toString(Consts.HEX).length==64 ){
    console.log('r= '+signature_r)
    console.log('s= '+signature_s)
    return {signature_r, signature_s,recid2 };
  }
}

/// ecrecover test: 

  var n = Consts.q;
  var e = new BigInteger(message,'16');
  var r = signature_r;
  var s = signature_s;

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = recid2 & 1;
  var isSecondKey = recid2 >> 1;

  // 1.1. Let x = r + jn.
  if (isSecondKey)
    r = utils.ec.curve.pointFromX((r.add(Consts.q)).toString(16), isYOdd);
  else
    r = utils.ec.curve.pointFromX(r.toString(16), isYOdd);

  var rInv = signature_r.modInv(Consts.q);
  var s1 = modulo(Consts.q.subtract(e).multiply(rInv),Consts.q);
  var s2 = modulo(s.multiply(rInv),Consts.q);

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  //console.log(utils.ec.g.mul(s1.toString(Consts.HEX)).add(r.mul(s2.toString(Consts.HEX))));
  //console.log(QQ)
///


}

function signVerify(serverCache,clientCache,message){
// used to validate change of paramters by validation a joint signature
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const messageTag  =  crypto.createHash('sha256').update(message).digest('hex');

  clientCache['messageTag'] = messageTag
  serverCache['messageTag'] = messageTag

 
  while(true){
    const { com1s, com2s } = serverSignStage1({serverCache,clientCache});
    const { tc, rc, R2 } = clientSignStage1({serverCache,clientCache});
    const { a1s, a2s, ts, rs, R1 } = serverSignStage2({ tc, rc, R2 ,serverCache,clientCache });
    const {c3,recid} = clientSignStage2({ a1s, R1, a2s, ts, rs, com1s, com2s,serverCache,clientCache });
    const {signature_r, signature_s,recid2,ver1,verR } = serverSignStage3({c3,serverCache,clientCache,recid});

  if(signature_r.toString(Consts.HEX).length==64 && signature_s.toString(Consts.HEX).length==64 ){
    console.log('ver1= '+ver1)
    console.log('verR= '+verR)
    if (ver1 ==verR){return true;}
    return false;
  }
}

/// ecrecover test: 

  var n = Consts.q;
  var e = new BigInteger(message,'16');
  var r = signature_r;
  var s = signature_s;

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = recid2 & 1;
  var isSecondKey = recid2 >> 1;

  // 1.1. Let x = r + jn.
  if (isSecondKey)
    r = utils.ec.curve.pointFromX((r.add(Consts.q)).toString(16), isYOdd);
  else
    r = utils.ec.curve.pointFromX(r.toString(16), isYOdd);

  var rInv = signature_r.modInv(Consts.q);
  var s1 = modulo(Consts.q.subtract(e).multiply(rInv),Consts.q);
  var s2 = modulo(s.multiply(rInv),Consts.q);

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  //console.log(utils.ec.g.mul(s1.toString(Consts.HEX)).add(r.mul(s2.toString(Consts.HEX))));
  //console.log(QQ)
///


}

module.exports = {
  sign,
  signVerify,
};