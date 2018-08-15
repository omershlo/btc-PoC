let bitcoin = require('bitcoinjs-lib')
const signM = require('./sign2Red_sid');
const signMPC = signM.sign;
const KeyGenM = require('./KeyGen_v2');
const KeyGenMPC = KeyGenM.KeyGen;

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

const networks = require('./bitcoinjs/src/networks');
const ECPair = require('./bitcoinjs/src/ecpair');
const TransactionBuilder = require('./bitcoinjs/src/transaction_builder');

// stage 1: MPC key GEN
/* 
const {serverCache,clientCache} = KeyGenMPC();


const Q1 =  serverCache['q1'];
const Q2 =  clientCache['q2'];
const X1 = serverCache['x1'];
const X2 = clientCache['x2'];
const Ckey = clientCache['ciphertext'];
const Q = Q1.mul(X2.toString(Consts.HEX));
const n = clientCache['paillierPublicKey'].n.toString(Consts.HEX);
const g = clientCache['paillierPublicKey'].g.toString(Consts.HEX);
const p = serverCache['keyPair'].privateKey.p.toString(Consts.HEX);
const q = serverCache['keyPair'].privateKey.q.toString(Consts.HEX);
const lambda = serverCache['keyPair'].privateKey.lambda.toString(Consts.HEX);
const preCalculatedDenominator = serverCache['keyPair'].privateKey.preCalculatedDenominator.toString(Consts.HEX);

console.log('Q1x: '+Q1.x.toString('hex'))
console.log('	')
console.log('Q1y: '+Q1.y.toString('hex'))
console.log('	')
console.log('Q2x: '+Q2.x.toString('hex'))
console.log('	')
console.log('Q2y: '+Q2.y.toString('hex'))
console.log('	')
console.log('Q: '+ Q.x.toString('hex'))
console.log('	')
console.log('Ckey: '+Ckey.toString(Consts.HEX))
console.log('	')
console.log('X1: '+X1.toString(Consts.HEX))
console.log('	')
console.log('X2: '+X2.toString(Consts.HEX))
console.log('	')
console.log('n: '+n)
console.log('	')
console.log('g: '+g)
console.log('	')
console.log('p: '+p)
console.log('	')
console.log('q: '+q)
console.log('	')
console.log('lambda: '+ lambda)
console.log('	')
console.log('preCalculatedDenominator: '+preCalculatedDenominator)
//Look at the last bit of the Y coordinate, add it to 0x02 and use that as the flag
const compByteThreshold = BigInteger(Q.y.toString('hex').substr(63,63),16).and(1);
var compByteVal = '02';
if(compByteThreshold.equals(1)){compByteVal = '03';}
else{compByteVal = '02';}

*/
//consts: 
const q1x = '50a37953fc0bc9d6fa373fc084f04846f6dba06a62a368731f76590b7600417d';
const q1y = '48be476d8d0d12384f98e3bd70ae141a63e5bb81998d4a9067b0abacc510ae5';
const q2x = '33ea9c161401e0d7a71d3fd1b0b79a23e365776e133e998c6a9581566a59605c';
const q2y = 'b150a529f03fc3ad8d0c3a2e32044d974e2a0076d31d6df5a2ca9474f7bf13db';
const Q1 = utils.ec.curve.point(q1x,q1y);
const Q2 = utils.ec.curve.point(q2x,q2y);
//const Q = '1ed29e32115bce4597362f4697b19cba14df44c15db1e9e1c4bec88ceecad739';
const Ckey = '1b4360298b75572ccd1bf5a7dd5227bb07a2946210d5bf7cfeb681ee861d049afd7e451a119cdd90d12f4e1f31b6a84c570357462e1b32999832f304c836b5dd57ef893d2b9409409e1471721f375f6f35bbd9046f2664658d9a2fd0fb0e54e3ae6c04c1b9faf3bd1a1cea45ba7ad7bd4ce61060fdf6b03d68817d0d7b74bf3d7662b958434db44f347088fbf5aaf3bd62f013e156bd867efd05936151d8be476c72091e4f9fe0c45a5c54d804538cd993776843478ec28d1f7f890251219ab097446bd99205193f751cafab13137a75a9e6eaf30b6ba287ea550f545cca77ebff7674c68a0382c146c7f7f93d077d68d266ed3690d629e53c189c73e512f5582';
const X1 = '4ed4e3a7bb76b8426e65077c23dd6f1e48d2c1e0e6233646da2791558e16394c';
const X2 = '6b57f4af6a083f3cc0ea33e160416471e111bc33f57940d5efd27b46a8c4d53';
const n = '14e8617767030c3384341e8f7f8df720e7bf30f1139a00840d563505e58610807c77c2853e92176a5ef4abeed6358135b7b2941f08332add661304bde274777aad8cd106c80b1ef335b57406131498f3345c341ab756e966777893da1bb07ad233d00e81ebf0abe4f28e2b0b65a519e9398f8c815406e4aca4deaf8f75021d1db';
const g = '208b1ebccd172bd0dac681848b32faa384b207d2de7e451eba1ab4a212a54a936634f1cd9c91abf3ba378dc3e2fa0df51d0e51ea6c871e7e1607d2ebab2f7b2c25115df73f883db8d53b34cce73a769fae07a72fe53bd215c0b99cc421d5b68feab35ee0d51507a8253304937ffa5b3cdb311478d587b4d884aeadf174b0aa467';
const p ='e19bd588d6e4d6c06742ac0a1224717a74870c71a2fe5d99ca644fdfa6afb7989b2035a5e41ae7cf6a87edac1236d22ea1798f1cfd0f4accd0fea5fa5ce86c05';
const q ='17b9637a0482945c70e1d7863390331341231491de67a270bf31fd78e40534f2c56590e849a1f0c3eeeab2a6573bd9f944d94ee939cc6ec815231aa4d17c38c5f';
const lambda = 'a7430bbb3818619c21a0f47bfc6fb9073df987889cd004206ab1a82f2c308403e3be1429f490bb52f7a55f76b1ac09adbd94a0f8419956eb309825ef13a3bbd43dcd81a1b0d1e955f2fb8df9f310f6425f85760df5fb08e0dd028b19ea02532f25c3d1fa2068652067d7cc526a2e966854f52532534c09be155d5457edbaecbc';
const preCalculatedDenominator = '5f2bec4a5ba23e0e974e5ca9d9a90b6e1f06033c5ae4610771690ab3c339e1a5e0a3ab6ca2772fb1c75a805fccbba51a1a103e9a43917c99780cd38112469c0e94cbd5ee97247a4456540396749d2e486ef4e37858491f6ca0ecf3b28d5ef458ee7518cb5874db60f254583a73fda1784e0ca00b05e5b883c0958125afa4721b';
//Look at the last bit of the Y coordinate, add it to 0x02 and use that as the flag
const Q = Q1.mul(X2.toString(Consts.HEX));
const compByteThreshold = BigInteger(Q.y.toString('hex').substr(63,63),16).and(1);
var compByteVal = '02';
if(compByteThreshold.equals(1)){compByteVal = '03';}
else{compByteVal = '02';}

//2MzA5qhkiocDXaiL1t8yoUUwjLZhcs4N9Q9
// creating addresses
var testnet = networks.testnet;
var mainnet = networks.mainnet;
var regtest = networks.regtest;
const compQ = compByteVal + Q.x.toString('hex');
const pubKey = Buffer.from(compQ, 'hex');

const keyPair = ECPair.fromPublicKey(pubKey, {network: regtest})
const { address, output } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey, network: regtest })
console.log("address: " +address);
// Create P2WPKH address A1 based on MPC public key
//    const keyPair = bitcoin.ECPair.fromWIF('Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct')
//    const { address } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey })
/*
var scriptPubKeyA1 = bitcoin.script.witnessPubKeyHash.output.encode(bitcoin.crypto.hash160(pubKey));
var addressA1 = bitcoin.address.fromOutputScript(scriptPubKeyA1,testnet); // not supported in bitcoin core 0.15.1
console.log("addressA1 = " + addressA1);
//Create P2SH(P2WPKH) address A2 based on MPC public key 
var redeemScript = scriptPubKeyA1;
var scriptPubKeyA2 = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(redeemScript))
var addressA2 = bitcoin.address.fromOutputScript(scriptPubKeyA2,testnet)

console.log(addressA1)
console.log(addressA2)

var keyPairs = [compQ].map(function (q) { return ECPair.fromPublicKeyBuffer(Buffer.from(q, 'hex'),testnet) }); 
var keyPair = keyPairs[0];
*/
var txb = new TransactionBuilder(regtest);

const txid = 'f29a46fddaa57221b27d6997ecdcb5bbd1dadff582af1359d259cde052139cbd';
const vout = 0;
txb.addInput(txid, vout, null, output);
console.log("output :" + output )
const sendTo = 'mztBSxU4psGyPUjRrUEfuJB6wKrqZKJ78M';
//const amount = 999800000;
txb.addOutput(sendTo,999800000);
//txb.addOutput('2MzA5qhkiocDXaiL1t8yoUUwjLZhcs4N9Q9',(5*100000000)* 0.9998);

const inputValue = 1000000000;
//console.log(redeemScript)
txb.sign(0, keyPair, null, null, inputValue);
//vin, keyPair, redeemScript, hashType, witnessValue, witnessScript
const rawSignedTx = txb.build().toHex();
console.log(rawSignedTx);

