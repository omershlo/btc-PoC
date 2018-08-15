
/*###############################################################################################*/
/*this version of KeyGen has the following properties : */
/* 1. Bulletproof with preprocessing */
/* 2. elliptic curve optimization  (Elliptic Red): to switch between changes need to be made to in consts.js and in utils.js*/
/* 3. optimizied ZK Paillier.*/
/*###############################################################################################*/
function compareCurvePoints(p1, p2) {
  return (p1.x.fromRed().toString(16) === p2.x.fromRed().toString(16)) &&
    (p1.y.fromRed().toString(16) === p2.y.fromRed().toString(16));
}


/*###############################################################################################*/
/*################################  SERVER    ##################################################*/
/*###############################################################################################*/
function serverStage1({serverCache,clientCache}) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  // ## (2.a) ##
  // Save x1 (private key) and Q1 (public key) in cache
  const x1 = pickRandom(BigInteger(2).pow(Consts.qBitLengthMinusOne));
  //while(Consts.qOver3.greater(x1)){
  //   x1 = pickRandom(BigInteger(2).pow(Consts.qBitLengthMinusOne));
 // }
 // console.log(x1)

  // ## (2.b) ##
  // Create and initialize EC context
  
  const q1 = utils.ec.g.mul(x1.toString(Consts.HEX));

  // ## (2.c) ##
  const a1 = pickRandom();
  const a1_q1_concat = a1.toString(Consts.HEX).concat(q1.x.fromRed().toString(16));
  const hash = crypto.createHash('sha256').update(a1_q1_concat).digest('hex');
  const com1 = modulo(new BigInteger(hash, Consts.HEX),Consts.q).toString(Consts.HEX);

  // ## (2.d) ##
  // Fiat Shamir heuristic
  const v = pickRandom(Consts.q.minus(1));
  const t = utils.ec.g.mul(v.toString(Consts.HEX));

  // c = H(t,G,Q1) mod (q)
  const t_g_q1_concat = t.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), q1.x.fromRed().toString(16));
  const t_g_q1_concat_hash = crypto.createHash('sha256').update(t_g_q1_concat).digest('hex');
  const c = modulo(new BigInteger(t_g_q1_concat_hash, Consts.HEX),Consts.q);

  // r = v -  c * x1
  const r = utils.moduloSubq(v,utils.moduloMulq(c,x1));



  //com2 = H(a2,t,r)
  const a2 = pickRandom();
  const a2_t_r_concat = a2.toString(Consts.HEX).concat(t.x.fromRed().toString(16), r.toString(Consts.HEX));
  //const com2 = modulo(new BigInteger(crypto.createHash('sha256').update(a2_t_r_concat).digest('hex')),Consts.q);
  const hash2 = crypto.createHash('sha256').update(a2_t_r_concat).digest('hex');
  const com2 = modulo(new BigInteger(hash2, Consts.HEX),Consts.q).toString(Consts.HEX);


  serverCache['x1'] = x1;
  serverCache['a1'] = a1;
  serverCache['a2'] = a2;
  serverCache['t'] = t;
  serverCache['r'] = r;
  serverCache['q1'] = q1;
  serverCache['com1'] = com1;
  serverCache['com2'] = com2;

  return { com1, com2 };
}

function serverStage2({ t2, r2, q2,serverCache,clientCache }) {
  serverCache['q2'] = q2;
  // Computing c2
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const t2_G_q2_concat = t2.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), q2.x.fromRed().toString(16));
  const t2_G_q2_concat_hash = crypto.createHash('sha256').update(t2_G_q2_concat).digest('hex');
  const c2 = modulo(new BigInteger(t2_G_q2_concat_hash, Consts.HEX),Consts.q);

  // Checking that t2 = G*r2+Q2*c2
  const r2Point = utils.ec.g.mul(r2.toString(Consts.HEX));
  const q2c2 = q2.mul(c2.toString(Consts.HEX));
  const t2_check = r2Point.add(q2c2);
  if (!compareCurvePoints(t2, t2_check)) {
    throw new Error('Calculated t2 is not equal between server and client - abort');
  }

  return {
    a1: serverCache.a1,
    a2: serverCache.a2,
    t: serverCache.t,
    r: serverCache.r,
    q1: serverCache.q1,
  };
}

function serverStage3({serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const x1 = serverCache.x1;
 // const builder = new KeyPairBuilder();
 // const keypair = builder.generateKeyPair();
 const keypair = serverCache['keyPair']
  const ciphertext = keypair.publicKey.encrypt(x1);
  const paillierPublicKey = keypair.publicKey;
  serverCache['phi'] = keypair.privateKey.phi;
  serverCache['N'] = keypair.publicKey.n;
  serverCache['q'] = keypair.privateKey.q;
  serverCache['p'] = keypair.privateKey.p;
  //serverCache['keyPair'] = keypair;
  serverCache['ciphertext'] = ciphertext;
  return {ciphertext, paillierPublicKey};
}

function zkPaillierServerStage1({challengeArray, e, zArray,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder,moduloAddq,moduloSubq,moduloMulq,BN,moduloMul} = helper();
  const aArray = [];
  const ziToTheN = [];
  const result2 = true;
  const n = serverCache['N'];
  const phi = serverCache['phi'];
  const p = serverCache['p'];
  const q = serverCache['q'];
  let A_X_concat = n.toString(Consts.HEX);
  const xiToThePhi = [];
  const xiToTheMinusE = [];
  const yArrayTag = [];
  let yTagConcat = ""; 
    //zkpaillier 3
  let i=0;
  while ( i < Consts.securityNum) { 
        //(A * B) mod C = (A mod C * B mod C) mod C
      ziToTheN[i] = moduloPow(zArray[i],n,n);
      //xiToThePhi[i] = moduloPow(challengeArray[i],phi,n);
      xiToTheMinusE[i] = moduloPow(challengeArray[i],e,n).modInv(n);
   //   aArray[i] = modulo(ziToTheN[i].multiply(xiToThePhi[i]).multiply(xiToTheMinusE[i]),n);
      aArray[i] = modulo(ziToTheN[i].multiply(xiToTheMinusE[i]),n);

      if(BigInteger.gcd(n,aArray[i])!=1 || BigInteger.gcd(n,challengeArray[i])!=1 || BigInteger.gcd(n,zArray[i])!=1){result2 = false;}
      i++;
      
  }

  //c : check e
  let j = 0;
  while ( j < Consts.securityNum) { 
        A_X_concat = A_X_concat.concat(challengeArray[j].toString(Consts.HEX),aArray[j].toString(Consts.HEX));
        j++;
        
      }
  
  const A_X_concat_hash = crypto.createHash('sha256').update(A_X_concat).digest('hex');
  const eServer = BigInteger(A_X_concat_hash,Consts.HEX);
  if (eServer.compare(e)!=0){result2 == false;}

  const dN = n.modInv(phi);
  const dp = modulo(dN, p.subtract(BigInteger.one))
  const dq = modulo(dN, q.subtract(BigInteger.one))
  let k =0 ; 
  
  while (k < Consts.securityNum){
    // chinese reminder therem: https://crypto.stackexchange.com/questions/2575/chinese-remainder-theorem-and-rsa
    const cp = modulo(challengeArray[k],p );
    const cq = modulo(challengeArray[k],q );
    const mp = moduloPow(cp,dp,p);
    const mq = moduloPow(cq,dq,q);
    const qinvp = q.modInv(p);
    const mtag = mq.add(q.multiply(moduloMul(qinvp,mp.subtract(mq),p)));
    yArrayTag[k] = mtag;
    //yArrayTag[k] = moduloPow(challengeArray[k], dN, n);
    yTagConcat = yTagConcat.concat(yArrayTag[k].toString(Consts.HEX));
    k++;
  }
  const h1 = crypto.createHash('sha256').update(yTagConcat).digest('hex');
  const hServer = BigInteger(h1,Consts.HEX);
  return {hServer, result2};
 
}


function xRangeProofServerStage1({codewordXComm,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  serverCache['codewordXComm'] = codewordXComm;
  const n = serverCache['N'];
  const w1 = [];
  const w2 = [];
  const s1 = [];
  const s2 = [];
  const fx = [];
  const gx = [];
  const v = pickRandom(BigInteger(2).pow(Consts.securityNum).minus(1));
  let i = 0;
  while(i< Consts.securityNum){
    w1[i] = pickRandomInRange(Consts.qOver3,Consts.qOver3.multiply(2));
    w2[i] = w1[i].subtract(Consts.qOver3);
    if(v.shiftRight(i).mod(2)!=0){const temp = w2[i];w2[i] = w1[i];w1[i]= temp;}
    s1[i] = pickRandom(n);
    s2[i] = pickRandom(n);
    fx[i] = serverCache['keyPair'].publicKey.encrypt(w1[i],s1[i]);
    gx[i] = serverCache['keyPair'].publicKey.encrypt(w2[i],s2[i]);
    i++;
  }
  serverCache['w1'] = w1;
  serverCache['w2'] = w2;
  serverCache['s1'] = s1;
  serverCache['s2'] = s2;

  return {fx,gx};
}

function xRangeProofServerStage2({codewordX,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const n = serverCache['N'];
  const result4= true;
  const codewordXComm = crypto.createHash('sha256').update(codewordX.toString(Consts.HEX)).digest('hex');
  const codewordXCommServer = BigInteger(codewordXComm,Consts.HEX);
  if (codewordXCommServer.compare(BigInteger(serverCache['codewordXComm'],Consts.HEX)!=0)) {result4 == false;}
  const w1x = [];
  const w2x = [];
  const s1x = [];
  const s2x = [];
  const g1x = [];
  const g2x = [];
  const Jx = [];
  let i =0;
  while (i < Consts.securityNum)
  {
    if(codewordX.shiftRight(i).mod(2).equals(BigInteger(0))){
      w1x[i] = serverCache['w1'][i];
      w2x[i] = serverCache['w2'][i];
      s1x[i] = serverCache['s1'][i];
      s2x[i] = serverCache['s2'][i];
    }
    else{
      w1x[i] = serverCache['w1'][i];
      w2x[i] = serverCache['w2'][i];
      s1x[i] = serverCache['s1'][i];
      s2x[i] = serverCache['s2'][i];
      if((serverCache['x1'].add(serverCache['w1'][i])).greater(Consts.qOver3) && (serverCache['x1'].add(serverCache['w1'][i])).lesser(Consts.qOver3.multiply(2))) {
       g1x[i] = serverCache['x1'].add(serverCache['w1'][i]);
       g2x[i] = modulo(serverCache['keyPair'].publicKey.r.multiply(serverCache['s1'][i]),n); 
       Jx[i] = 1;         
      }
      if((serverCache['x1'].add(serverCache['w2'][i])).greater(Consts.qOver3) && (serverCache['x1'].add(serverCache['w2'][i])).lesser(Consts.qOver3.multiply(2))) {
       g1x[i] = serverCache['x1'].add(serverCache['w2'][i]);
       g2x[i] = modulo(serverCache['keyPair'].publicKey.r.multiply(serverCache['s2'][i]),n);    
       Jx[i] = 2;
      }

    }
    i++;
  }
  

  return {w1x,w2x,s1x,s2x,g1x,g2x,Jx, result4}
}


function pdlServerStage1({cTag,cTagTag,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const alpha = serverCache['keyPair'].decrypt(cTag);
  serverCache['alpha'] = alpha;
  const QHat = utils.ec.g.mul(alpha.toString(Consts.HEX));
  serverCache['QHat'] = QHat;
  const cHatHash = crypto.createHash('sha256').update(QHat.x.fromRed().toString(16)).digest('hex');
  const cHat = BigInteger(cHatHash,Consts.HEX);
  return cHat;
}

function pdlServerStage2({a,b,serverCache,ClientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  var result6 = true;
  if(serverCache['alpha'].compare(modulo(a.multiply(serverCache['x1']).add(b),serverCache['keyPair'].publicKey.n))!=0){result6 = false;}
  const QHat = serverCache['QHat'];
  return {result6, QHat}
}
/*###############################################################################################*/
/*################################  CLIENT    ##################################################*/
/*###############################################################################################*/
function clientStage1({serverCache,clientCache}) {
  const {crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder,moduloAddq,moduloSubq,moduloMulq,BN} = helper();
  // ## 3.a ##
  const x2 = pickRandom(Consts.q);

  // ## (3.b) ##

  const q2 = utils.ec.g.mul(x2.toString(Consts.HEX));


  // ## (3.c) ##
  // ZK proof of DL
  const v2 = pickRandom(Consts.q.minus(1));
  const t2 = utils.ec.g.mul(v2.toString(Consts.HEX));

  // c2 = H(t2,G,Q2) mod (q)
  const t2_G_q2_concat = t2.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), q2.x.fromRed().toString(16));
  const t2_G_q2_concat_hash = crypto.createHash('sha256').update(t2_G_q2_concat).digest('hex');
  const c2 = modulo(new BigInteger(t2_G_q2_concat_hash, Consts.HEX),Consts.q);

  // r2 = v2 -  c2 * x2
  //const r2 = v2.minus(c2.multiply(x2));
  const r2 = utils.moduloSubq(v2,utils.moduloMulq(c2,x2));
  clientCache['x2'] = x2;
  clientCache['q2'] = q2;

  return { t2, r2, q2 };
}

function clientStage2({ a1, q1, a2, t, r, com1, com2,serverCache,clientCache }) {
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  clientCache['q1'] = q1;
  // checks com1 = H(a1,Q1) mod(q) and com2 = H(a2,t,r) mod(q) if not - abort
  const a1_q1_concat = a1.toString(Consts.HEX).concat(q1.x.fromRed().toString(16));
  const a1_q1_concat_hash = crypto.createHash('sha256').update(a1_q1_concat).digest('hex');
  const com1_check = modulo(BigInteger(a1_q1_concat_hash, Consts.HEX),Consts.q);

  if (com1_check.toString(Consts.HEX) !== com1.toString(Consts.HEX)) {
    throw new Error('com1 check failed - abort');
  }

  const a2_t_r_concat = a2.toString(Consts.HEX).concat(t.x.fromRed().toString(16), r.toString(Consts.HEX));
  const a2_t_r_concat_hash = crypto.createHash('sha256').update(a2_t_r_concat).digest('hex');
  const com2_check = modulo(new BigInteger(a2_t_r_concat_hash, Consts.HEX),Consts.q);

  if (com2_check.toString(Consts.HEX) !== com2.toString(Consts.HEX)) {
    throw new Error('com2 check failed - abort');
  }

  // compute c = H(t,G,Q1) mod (q)

  const t_g_q1_concat = t.x.fromRed().toString(16).concat(utils.ec.g.x.fromRed().toString(16), q1.x.fromRed().toString(16));
  const t_g_q1_concat_hash = crypto.createHash('sha256').update(t_g_q1_concat).digest('hex');
  const c = modulo(new BigInteger(t_g_q1_concat_hash, Consts.HEX),Consts.q);

  // calculate t = G*r+Q1*c\
  const rPoint = utils.ec.g.mul(r.toString(Consts.HEX));
  const q1c = q1.mul(c.toString(Consts.HEX));
  const t_check = rPoint.add(q1c);

  if (!compareCurvePoints(t, t_check)) {
    throw new Error('t check has failed - abort');
  }

  return true;
}

function zkPaillierClientStage1({paillierPublicKey,ciphertext,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const n = paillierPublicKey.n;
  clientCache['paillierPublicKey'] = paillierPublicKey;
  clientCache['ciphertext'] = ciphertext;
  clientCache['n'] = n;
  const yArray=[];
  const challengeArray=[];
  const randomArray = [];
  const aArray = [];
  const zArray = [];
  let A_X_concat = n.toString(Consts.HEX);
  let i=0;
  //zkpaillier 1
  while ( i < Consts.securityNum) { 
      const candidateGroupElement = pickRandom(n.subtract(BigInteger.one));
      if(BigInteger.gcd(n,candidateGroupElement)==1){
        yArray[i] = candidateGroupElement;
        challengeArray[i] = moduloPow(yArray[i],n,n);
        i++;
      }
  }
  //zkpaillier 2
  let j=0;
  while ( j < Consts.securityNum) { 
      const r = pickRandom(n.subtract(BigInteger.one));
      if(BigInteger.gcd(n,r)==1){
        randomArray[j] = r;
        aArray[j] = moduloPow(randomArray[j],n,n);
        A_X_concat = A_X_concat.concat(challengeArray[j].toString(Consts.HEX),aArray[j].toString(Consts.HEX));
        j++;
        
      }
  }

  const A_X_concat_hash = crypto.createHash('sha256').update(A_X_concat).digest('hex');
  const e = BigInteger(A_X_concat_hash,Consts.HEX);

  let k=0;
  while ( k < Consts.securityNum) { 
    //(A * B) mod C = (A mod C * B mod C) mod C
      zArray[k] = modulo(modulo(randomArray[k],n).multiply(moduloPow(yArray[k],e,n)),n);
      k++;
        
  }
  clientCache['yArray'] = yArray;
  return {challengeArray, e, zArray};

}
function zkPaillierClientStage2({hServer,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  yArray = clientCache['yArray'];
  let yArrayConcat = "";
  let v =0;
  while (v<Consts.securityNum){
    yArrayConcat = yArrayConcat.concat(yArray[v].toString(Consts.HEX));
    v++;
  }

  const yArrayConcat_hash = crypto.createHash('sha256').update(yArrayConcat).digest('hex');
  const hClient = BigInteger(yArrayConcat_hash,Consts.HEX);
  if (hClient.compare(hServer)!=0){return false;}
  return true;
}


function xRangeProofClientStage1({serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const codewordX = pickRandom(BigInteger(2).pow(Consts.securityNum).minus(1));
  clientCache['codewordX'] = codewordX;
  const codewordXComm = crypto.createHash('sha256').update(codewordX.toString(Consts.HEX)).digest('hex');
  return codewordXComm;
}

function xRangeProofClientStage2({fx,gx,serverCache,clientCache}){
  clientCache['fx'] = fx;
  clientCache['gx'] = gx;
  return clientCache['codewordX'];
}


function xRangeProofClientStage3({w1x,w2x,s1x,s2x,g1x,g2x,Jx,serverCache,clientCache}){
  fx = clientCache['fx'];
  gx= clientCache['gx'];
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const n = clientCache['paillierPublicKey'].n;
  const nSquare = n.pow(2);
  const ciphertext = modulo(clientCache['ciphertext'],nSquare);
  const codewordX = clientCache['codewordX'];
  var result5 = true;
  let i=0;
  while(i<Consts.securityNum){
    bitValue = codewordX.shiftRight(i).mod(2);
    if(bitValue.equals(BigInteger(0))){

      if(clientCache['paillierPublicKey'].encrypt(w1x[i],s1x[i]).compare(clientCache['fx'][i])!=0){result5 = false;}
      if(clientCache['paillierPublicKey'].encrypt(w2x[i],s2x[i]).compare(clientCache['gx'][i])!=0){result5 = false;}
      if((w2x[i].subtract(w1x[i])) .abs().compare(Consts.qOver3)!=0) {result5 = false;}
    }
    if(bitValue.equals(BigInteger(1))){
      if(Jx[i]==1){
        const fxMod = modulo(fx[i],nSquare);
        if(modulo(ciphertext.multiply(fxMod),nSquare).compare(clientCache['paillierPublicKey'].encrypt(g1x[i],g2x[i]))!=0){result5= false;console.log(result5)}
        if(g1x[i].lesser(Consts.qOver3)|| g1x[i].greater(Consts.qOver3.multiply(2))){result5=false;}
      }
      if(Jx[i]==2){
        const gxMod = modulo(gx[i],nSquare);
        if(modulo(ciphertext.multiply(gxMod),nSquare).compare(clientCache['paillierPublicKey'].encrypt(g1x[i],g2x[i]))!=0){result5= false;}
        if(g1x[i].lesser(Consts.qOver3)|| g1x[i].greater(Consts.qOver3.multiply(2))){result5=false;}
      }

    }
    i++;
  }
  return result5;
}


function pdlClientStage1({serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const a = pickRandom(Consts.q);
  const b = pickRandom(Consts.q.pow(2));
  clientCache['A'] = a;
  clientCache['B'] = b;
  const n = clientCache['paillierPublicKey'].n;
  const nSquare = n.pow(2);
  const r = pickRandom(n)
  const ciphertext = clientCache['ciphertext'];
  //ac+b
  const cTag = modulo(modulo(clientCache['paillierPublicKey'].encrypt(b,r),nSquare).multiply(moduloPow(ciphertext,a,nSquare)),nSquare);
  const abHash = crypto.createHash('sha256').update(a.toString(Consts.HEX).concat(b.toString(Consts.HEX))).digest('hex');
  const cTagTag = BigInteger(abHash,Consts.HEX);
  const q1 = clientCache['q1'];
  clientCache['QTag'] = q1.mul(a.toString(Consts.HEX)).add(utils.ec.g.mul(b.toString(Consts.HEX)));
  return {cTag,cTagTag};
}

function pdlClientStage2({cHat,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();

  clientCache['cHat'] = cHat;
  const a=clientCache['A'];
  const b= clientCache['B'];
  return({a,b});

}

function pdlClientstage3({QHat,serverCache,clientCache}){
  const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  var result7 = true;
  const cHatHashServer = crypto.createHash('sha256').update(QHat.x.fromRed().toString(16)).digest('hex');
  const cHatServer = BigInteger(cHatHashServer,Consts.HEX);
  if(cHatServer.compare(clientCache['cHat'])!=0){result7 = false;}
  return result7;
}


/*###################################### TEST KeyGen #####################################*/
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
  const moduloAddq = utils.moduloAddq;
  const moduloSubq = utils.moduloSubq;
  const moduloMulq = utils.moduloMulq;
  const moduloMul = utils.moduloMul;
  const KeyPairBuilder = require('./paillier/keypair-builder');
  var BN = require('bn.js');

  return {crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder,moduloAddq,moduloSubq,moduloMulq,BN,moduloMul};
}
function KeyGen(){
    const { crypto,BigInteger,EC,Consts,utils,pickRandom,pickRandomInRange,modulo,moduloPow,KeyPairBuilder} = helper();
  const serverCache = {};
  const clientCache = {};
    const { com1, com2 } = serverStage1({serverCache,clientCache});

  const builder = new KeyPairBuilder();
  const keypair = builder.generateKeyPair();
  serverCache['keyPair'] = keypair;
  var start = new Date().getTime();

  
  const { t2, r2, q2 } = clientStage1({serverCache,clientCache});
  
  const { a1, a2, t, r, q1 } = serverStage2({ t2, r2, q2 ,serverCache,clientCache});
  
  const result = clientStage2({ a1, q1, a2, t, r, com1, com2 ,serverCache,clientCache});
  if(result == false){} //abort
    console.log(result)
   //#stage 6
  const { ciphertext, paillierPublicKey } = serverStage3({serverCache,clientCache});
  
  // zk paillier 1 + 2
  const {challengeArray, e, zArray} = zkPaillierClientStage1({paillierPublicKey,ciphertext,serverCache,clientCache});
  // zk paillier 3
  const {hServer, result2} = zkPaillierServerStage1({challengeArray, e, zArray,serverCache,clientCache});
  if(result2 == false){} //abort
    console.log(result2)
  const result3 = zkPaillierClientStage2({hServer,serverCache,clientCache});
  if(result3 == false){} //abort
  console.log(result3)


  //range proof: 
  const codewordXComm = xRangeProofClientStage1({serverCache,clientCache});
  
  const {fx,gx} = xRangeProofServerStage1({codewordXComm,serverCache,clientCache});
  
  const codewordX = xRangeProofClientStage2({fx,gx,serverCache,clientCache});
  
  const {w1x,w2x,s1x,s2x,g1x,g2x,Jx,result4} = xRangeProofServerStage2({codewordX,serverCache,clientCache});
  if(result4 == false){} //abort
  console.log(result4)
  const result5 = xRangeProofClientStage3({w1x,w2x,s1x,s2x,g1x,g2x,Jx,serverCache,clientCache});
  if(result5 == false){} //abort
  console.log(result5)
  

  // PDL proof (6.1)
  const {cTag,cTagTag} = pdlClientStage1({serverCache,clientCache});
  
  const cHat = pdlServerStage1({cTag,cTagTag,serverCache,clientCache});
  
  const {a,b} = pdlClientStage2({cHat,serverCache,clientCache});
  
  const {result6, QHat} = pdlServerStage2({a,b,serverCache,clientCache})
  if(result6 == false){} //abort
  console.log(result6)

  const result7 = pdlClientstage3({QHat,serverCache,clientCache});
  if(result7 == false){} //abort
  console.log(result7)

  var elapsed = new Date().getTime() - start; 
  console.log(elapsed)
  return ({serverCache,clientCache});
}


// after first key gen we are using the keyGen routine as part of refrashing keys //
function KeyGenNotFirstTime({serverCache,clientCache}){
   const { com1, com2 } = serverStage1({serverCache,clientCache});

  var start = new Date().getTime();
 
  
  const { t2, r2, q2 } = clientStage1({serverCache,clientCache});
  
  const { a1, a2, t, r, q1 } = serverStage2({ t2, r2, q2 ,serverCache,clientCache});
  
  const result = clientStage2({ a1, q1, a2, t, r, com1, com2 ,serverCache,clientCache});
  if(result == false){} //abort
    console.log(result)
   //#stage 6
  const { ciphertext, paillierPublicKey } = serverStage3({serverCache,clientCache});
  
  // zk paillier 1 + 2
  const {challengeArray, e, zArray} = zkPaillierClientStage1({paillierPublicKey,ciphertext,serverCache,clientCache});
  // zk paillier 3
  const {hServer, result2} = zkPaillierServerStage1({challengeArray, e, zArray,serverCache,clientCache});
  if(result2 == false){} //abort
    console.log(result2)
  const result3 = zkPaillierClientStage2({hServer,serverCache,clientCache});
  if(result3 == false){} //abort
  console.log(result3)

  //range proof: 
    //range proof: 
  const codewordXComm = xRangeProofClientStage1({serverCache,clientCache});
  
  const {fx,gx} = xRangeProofServerStage1({codewordXComm,serverCache,clientCache});
  
  const codewordX = xRangeProofClientStage2({fx,gx,serverCache,clientCache});
  
  const {w1x,w2x,s1x,s2x,g1x,g2x,Jx,result4} = xRangeProofServerStage2({codewordX,serverCache,clientCache});
  if(result4 == false){} //abort
  console.log(result4)
  const result5 = xRangeProofClientStage3({w1x,w2x,s1x,s2x,g1x,g2x,Jx,serverCache,clientCache});
  if(result5 == false){} //abort
  console.log(result5)
  


  // PDL proof (6.1)
  const {cTag,cTagTag} = pdlClientStage1({serverCache,clientCache});
  
  const cHat = pdlServerStage1({cTag,cTagTag,serverCache,clientCache});
  
  const {a,b} = pdlClientStage2({cHat,serverCache,clientCache});
  
  const {result6, QHat} = pdlServerStage2({a,b,serverCache,clientCache})
  if(result6 == false){} //abort
  console.log(result6)

  const result7 = pdlClientstage3({QHat,serverCache,clientCache});
  if(result7 == false){} //abort
  console.log(result7)

  var elapsed = new Date().getTime() - start; 
  console.log(elapsed)
  return ;
}

//KeyGen();

module.exports = {
  KeyGen,
  KeyGenNotFirstTime,
};