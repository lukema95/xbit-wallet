/*
* Parse email
*/
const { promisify } = require('util')
const crypto = require('crypto')
const NodeRSA = require('node-rsa')
const Signature = require('dkim-signature')
const processHeader = require('dkim/lib/process-header')
const processBody = require('dkim/lib/process-body')
const getKey = promisify(require('dkim/lib/get-key'))

const algorithms = {
  RSASHA1: 0,
  RSASHA256: 1
}

const parseEmail = email => {
  return new Promise(async (resolve, reject) => {
    // get dkims
    const dkims = parse(email).dkims.map(dkim => {
      const algorithm = dkim.algorithm
        .split('-')
        .pop()
        .toUpperCase()

      const bodyHashMatched =
        new crypto.createHash(algorithm)
          .update(dkim.processedBody)
          .digest()
          .compare(dkim.signature.hash) !== 0

      if (bodyHashMatched) {
        return reject('body hash did not verify')
      }

      const hash = crypto
        .createHash(algorithm)
        .update(dkim.processedHeader)
        .digest()

      return {
        ...dkim,
        hash
      }
    })

    // get dns records
    const publicKeys = await Promise.all(
      dkims.map(dkim =>
        getPublicKey({
          domain: dkim.signature.domain,
          selector: dkim.signature.selector
        })
      )
    )
      .then(entries => {
        return entries.map(entry => {
          const { publicKey } = entry
          const { exponent, modulus } = publicKeyToComponents(publicKey)

          return {
            ...entry,
            exponent,
            modulus
          }
        })
      })
      .catch(reject)

    return resolve(
      dkims.map((dkim, i) => {
        const solidityData = rawDataToSolidity({
          algorithm: dkim.algorithm,
          hash: dkim.hash,
          processHeader: dkim.processedHeader,
          signature: dkim.signature.signature,
          exponent: publicKeys[i].exponent,
          modulus: publicKeys[i].modulus
        })

        return {
          ...dkim,
          ...publicKeys[i],
          solidityData
        }
      })
    )
  })
}

const parse = email => {
  const { header, body } = emailToHeaderAndBody(email)
  const dkims = getDkims(header).map(dkim => {
    const signature = Signature.parse(dkim.entry.value)

    const sigBody =
      signature.length != null ? body.slice(0, signature.length) : body

    const processedBody = processBody(
      sigBody,
      signature.canonical.split('/').pop()
    )

    let processedHeader = processHeader(
      dkim.headers,
      signature.headers,
      signature.canonical.split('/').shift()
    )
    processedHeader = processedHeader.toString('hex')

    const algorithm = signature.algorithm.toUpperCase()

    return {
      ...dkim,
      signature,
      processedBody,
      processedHeader,
      algorithm
    }
  })

  return {
    header,
    body,
    dkims
  }
}

const getPublicKey = ({ domain, selector }) => {
  return getKey(domain, selector).then(key => {
    const publicKey =
      '-----BEGIN PUBLIC KEY-----\n' +
      key.key.toString('base64') +
      '\n-----END PUBLIC KEY-----'

    return {
      domain,
      selector,
      publicKey
    }
  })
}

const rawDataToSolidity = rawData => ({
  algorithm: algorithms[rawData.algorithm.replace('-', '')],
  hash: '0x' + rawData.hash.toString('hex'),
  processHeader: headerToSolidityBytes(rawData.processHeader),
  signature: '0x' + rawData.signature.toString('hex'),
  exponent: '0x' + rawData.exponent.toString(16),
  modulus: '0x' + rawData.modulus.toString('hex').slice(2)
})

const headerToSolidityBytes = (header) => {
  const utf8Bytes = new TextEncoder().encode(header)
  const length = utf8Bytes.length
  const lengthBytes = new Uint8Array(4)
  lengthBytes[0] = (length >> 24) & 0xff
  lengthBytes[1] = (length >> 16) & 0xff
  lengthBytes[2] = (length >> 8) & 0xff
  lengthBytes[3] = length & 0xff
  const bytes = new Uint8Array(length + 4)
  bytes.set(lengthBytes, 0)
  bytes.set(utf8Bytes, 4)

  const solidityBytes = '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  return solidityBytes
}

const emailToHeaderAndBody = email => {
  const boundary = email.indexOf('\r\n\r\n')
  if (boundary === -1) {
    throw Error('no header boundary found')
  }

  const header = email.slice(0, boundary)
  const body = email.slice(boundary + 4)

  return {
    boundary,
    header,
    body
  }
}

const publicKeyToComponents = publicKey => {
  const parsed = new NodeRSA(publicKey)
  const { e: exponent, n: modulus } = parsed.exportKey('components-public')

  return {
    exponent,
    modulus
  }
}

const getDkimEntry = dkim => {
  const [name, ...rest] = dkim.split(':')

  return {
    name,
    value: rest.join(':').slice(1)
  }
}

const getDkims = header => {
  return header
    .split(/\r\n(?=[^\x20\x09]|$)/g)
    .map((h, i, allHeaders) => {
      if (isDKIM(h)) {
        // remove DKIM headers
        const headers = allHeaders.filter(v => !isDKIM(v))
        // add one DKIM header
        headers.unshift(h)

        return {
          entry: getDkimEntry(h),
          headers
        }
      }

      return undefined
    })
    .filter(v => !!v)
}

const isDKIM = key => /^(DKIM-Signature|X-Google-DKIM-Signature)/.test(key)

module.exports = parseEmail
