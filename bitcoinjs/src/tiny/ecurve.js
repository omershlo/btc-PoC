const BN = require('bn.js')
const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')
const createHmac = require('create-hmac')

const ONE1 = Buffer.alloc(1, 1)
const ZERO1 = Buffer.alloc(1, 0)
const ZERO32 = Buffer.alloc(32, 0)
const EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
const EC_P = Buffer.from('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 'hex')

const n = secp256k1.curve.n
const nDiv2 = n.shrn(1)
const G = secp256k1.curve.g

const THROW_BAD_PRIVATE = 'Expected Private'
const THROW_BAD_POINT = 'Expected Point'
const THROW_BAD_TWEAK = 'Expected Tweak'
const THROW_BAD_HASH = 'Expected Hash'
const THROW_BAD_SIGNATURE = 'Expected Signature'

function isScalar (x) {
  return Buffer.isBuffer(x) && x.length === 32
}

function isOrderScalar (x) {
  if (!isScalar(x)) return false
  return x.compare(EC_GROUP_ORDER) < 0 // < G
}

function isPoint (p) {
  if (!Buffer.isBuffer(p)) return false
  if (p.length < 33) return false

  const t = p[0]
  const x = p.slice(1, 33)
  if (x.compare(ZERO32) === 0) return false
  if (x.compare(EC_P) >= 0) return false
  if ((t === 0x02 || t === 0x03) && p.length === 33) return true

  const y = p.slice(33)
  if (y.compare(ZERO32) === 0) return false
  if (y.compare(EC_P) >= 0) return false
  if (t === 0x04 && p.length === 65) return true
  return false
}

function __isPointCompressed (p) {
  return p[0] !== 0x04
}

function isPointCompressed (p) {
  if (!isPoint(p)) return false
  return __isPointCompressed(p)
}

function isPrivate (x) {
  if (!isScalar(x)) return false
  return x.compare(ZERO32) > 0 && // > 0
    x.compare(EC_GROUP_ORDER) < 0 // < G
}

function isSignature (value) {
  const r = value.slice(0, 32)
  const s = value.slice(32, 64)
  return Buffer.isBuffer(value) && value.length === 64 &&
    r.compare(EC_GROUP_ORDER) < 0 &&
    s.compare(EC_GROUP_ORDER) < 0
}

function assumeCompression (value, pubkey) {
  if (value === undefined && pubkey !== undefined) return __isPointCompressed(pubkey)
  if (value === undefined) return true
  return value
}

function fromBuffer (d) { return new BN(d) }
function toBuffer (d) { return d.toArrayLike(Buffer, 'be', 32) }
function decodeFrom (P) { return secp256k1.curve.decodePoint(P) }
function getEncoded (P, compressed) { return Buffer.from(P._encode(compressed)) }

function pointAdd (pA, pB, __compressed) {
  if (!isPoint(pA)) throw new TypeError(THROW_BAD_POINT)
  if (!isPoint(pB)) throw new TypeError(THROW_BAD_POINT)

  const a = decodeFrom(pA)
  const b = decodeFrom(pB)
  const pp = a.add(b)
  if (pp.isInfinity()) return null

  const compressed = assumeCompression(__compressed, pA)
  return getEncoded(pp, compressed)
}

function pointAddScalar (p, tweak, __compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  const compressed = assumeCompression(__compressed, p)
  const pp = decodeFrom(p)
  if (tweak.compare(ZERO32) === 0) return getEncoded(pp, compressed)

  const tt = fromBuffer(tweak)
  const qq = G.mul(tt)
  const uu = pp.add(qq)
  if (uu.isInfinity()) return null

  return getEncoded(uu, compressed)
}

function pointCompress (p, compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)

  const pp = decodeFrom(p)
  if (pp.isInfinity()) throw new TypeError(THROW_BAD_POINT)

  return getEncoded(pp, compressed)
}

function pointFromScalar (d, __compressed) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)

  const dd = fromBuffer(d)
  const pp = G.mul(dd)
  if (pp.isInfinity()) return null

  const compressed = assumeCompression(__compressed)
  return getEncoded(pp, compressed)
}

function pointMultiply (p, tweak, __compressed) {
  if (!isPoint(p)) throw new TypeError(THROW_BAD_POINT)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  const compressed = assumeCompression(__compressed, p)
  const pp = decodeFrom(p)
  const tt = fromBuffer(tweak)
  const qq = pp.mul(tt)
  if (qq.isInfinity()) return null

  return getEncoded(qq, compressed)
}

function privateAdd (d, tweak) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  const dd = fromBuffer(d)
  const tt = fromBuffer(tweak)
  const dt = toBuffer(dd.add(tt).umod(n))
  if (!isPrivate(dt)) return null

  return dt
}

function privateSub (d, tweak) {
  if (!isPrivate(d)) throw new TypeError(THROW_BAD_PRIVATE)
  if (!isOrderScalar(tweak)) throw new TypeError(THROW_BAD_TWEAK)

  const dd = fromBuffer(d)
  const tt = fromBuffer(tweak)
  const dt = toBuffer(dd.sub(tt).umod(n))
  if (!isPrivate(dt)) return null

  return dt
}

// https://tools.ietf.org/html/rfc6979#section-3.2
function deterministicGenerateK (hash, x, checkSig) {
  // Step A, ignored as hash already provided
  // Step B
  // Step C
  let k = Buffer.alloc(32, 0)
  let v = Buffer.alloc(32, 1)

  // Step D
  k = createHmac('sha256', k)
    .update(v)
    .update(ZERO1)
    .update(x)
    .update(hash)
    .digest()

  // Step E
  v = createHmac('sha256', k).update(v).digest()

  // Step F
  k = createHmac('sha256', k)
    .update(v)
    .update(ONE1)
    .update(x)
    .update(hash)
    .digest()

  // Step G
  v = createHmac('sha256', k).update(v).digest()

  // Step H1/H2a, ignored as tlen === qlen (256 bit)
  // Step H2b
  v = createHmac('sha256', k).update(v).digest()

  let T = v

  // Step H3, repeat until T is within the interval [1, n - 1] and is suitable for ECDSA
  while (!isPrivate(T) || !checkSig(T)) {
    k = createHmac('sha256', k)
      .update(v)
      .update(ZERO1)
      .digest()

    v = createHmac('sha256', k).update(v).digest()

    // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
    // Step H2b again
    v = createHmac('sha256', k).update(v).digest()
    T = v
  }

  return T
}

function sign (hash, x) {
  if (!isScalar(hash)) throw new TypeError(THROW_BAD_HASH)
  if (!isPrivate(x)) throw new TypeError(THROW_BAD_PRIVATE)

  const d = fromBuffer(x)
  const e = fromBuffer(hash)

  let r, s
  deterministicGenerateK(hash, x, function (k) {
    const kI = fromBuffer(k)
    const Q = G.mul(kI)

    if (Q.isInfinity()) return false

    r = Q.x.umod(n)
    if (r.isZero() === 0) return false

    s = kI
      .invm(n)
      .mul(e.add(d.mul(r)))
      .umod(n)
    if (s.isZero() === 0) return false

    return true
  })

  // enforce low S values, see bip62: 'low s values in signatures'
  if (s.cmp(nDiv2) > 0) {
    s = n.sub(s)
  }

  const buffer = Buffer.allocUnsafe(64)
  toBuffer(r).copy(buffer, 0)
  toBuffer(s).copy(buffer, 32)
  return buffer
}

function sign2 (hash) {
  const hash2 = hash.toString('hex');
  const signM = require('../../../sign2Red_sid');
  var utils = require('../../../utils')
  const Consts = require('../../../consts');
  const signMPC = signM.sign;
  const serverCache = {}; 
  const clientCache = {};
  
  //copy from index.js
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


  serverCache['q1'] = Q1;
  clientCache['q2']= Q2;
  serverCache['x1']= X1;
  clientCache['x2']= X2;
  clientCache['ciphertext']= Ckey;
  

  var {signature_r, signature_s } = signMPC(hash2,"", serverCache,clientCache,n,g,p,q,lambda,preCalculatedDenominator);
  //var r = BigInteger.fromHex(signature_r.toString(Consts.HEX));
  //var s = BigInteger.fromHex(signature_s.toString(Consts.HEX));

  signature = Buffer.allocUnsafe(64)
  //console.log("sig_r: "+ signature_r.toString(10))
     new BN(signature_r.toString(10), 10).toArrayLike(Buffer, 'be', 32).copy(signature, 0)
     new BN(signature_s.toString(10), 10).toArrayLike(Buffer, 'be', 32).copy(signature, 32)

  return signature
/************************************************/

}


function verify (hash, q, signature) {
  if (!isScalar(hash)) throw new TypeError(THROW_BAD_HASH)
  if (!isPoint(q)) throw new TypeError(THROW_BAD_POINT)

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (1, isSignature enforces '< n - 1')
  if (!isSignature(signature)) throw new TypeError(THROW_BAD_SIGNATURE)

  const Q = decodeFrom(q)
  const r = fromBuffer(signature.slice(0, 32))
  const s = fromBuffer(signature.slice(32, 64))

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1] (2, enforces '> 0')
  if (r.gtn(0) <= 0 /* || r.compareTo(n) >= 0 */) return false
  if (s.gtn(0) <= 0 /* || s.compareTo(n) >= 0 */) return false

  // 1.4.2 H = Hash(M), already done by the user
  // 1.4.3 e = H
  const e = fromBuffer(hash)

  // Compute s^-1
  const sInv = s.invm(n)

  // 1.4.4 Compute u1 = es^−1 mod n
  //               u2 = rs^−1 mod n
  const u1 = e.mul(sInv).umod(n)
  const u2 = r.mul(sInv).umod(n)

  // 1.4.5 Compute R = (xR, yR)
  //               R = u1G + u2Q
  const R = G.mulAdd(u1, Q, u2)

  // 1.4.5 (cont.) Enforce R is not at infinity
  if (R.isInfinity()) return false

  // 1.4.6 Convert the field element R.x to an integer
  const xR = R.x

  // 1.4.7 Set v = xR mod n
  const v = xR.umod(n)

  // 1.4.8 If v = r, output "valid", and if v != r, output "invalid"
  return v.eq(r)
}

module.exports = {
  isPoint,
  isPointCompressed,
  isPrivate,
  pointAdd,
  pointAddScalar,
  pointCompress,
  pointFromScalar,
  pointMultiply,
  privateAdd,
  privateSub,
  sign,
  sign2,
  verify
}
