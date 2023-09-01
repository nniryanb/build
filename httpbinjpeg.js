// Author @iryanb Noname Security 1.13.2023

import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from "k6/crypto";
import encoding from "k6/encoding";

const algToHash = {
    HS256: "sha256",
    HS384: "sha384",
    HS512: "sha512"
};


export let options = {

  stages: [
    { duration: '11s', target: 1000 },
    { duration: '59m', target: 1000 },
    { duration: '49s', target: 1000 },
  ],
};


function sign(data, hashAlg, secret) {
    let hasher = crypto.createHMAC(hashAlg, secret);
    hasher.update(data);

    // Some manual base64 rawurl encoding as `Hasher.digest(encodingType)`
    // doesn't support that encoding type yet.
    return hasher.digest("base64").replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}

function encode(payload, secret, algorithm) {
    algorithm = algorithm || "HS256";
    let header = encoding.b64encode(JSON.stringify({ typ: "JWT", alg: algorithm }), "rawurl");
    payload = encoding.b64encode(JSON.stringify(payload), "rawurl");
    let sig = sign(header + "." + payload, algToHash[algorithm], secret);
    return [header, payload, sig].join(".");
}

function decode(token, secret, algorithm) {
    let parts = token.split('.');
    let header = JSON.parse(encoding.b64decode(parts[0], "rawurl"));
    let payload = JSON.parse(encoding.b64decode(parts[1], "rawurl"));
    algorithm = algorithm || algToHash[header.alg];
    if (sign(parts[0] + "." + parts[1], algorithm, secret) != parts[2]) {
        throw Error("JWT signature verification failed");
    }
    return payload;
}

export default function () {
  //replace the subkey value with the API Subscription Key qp value authorized by this api gateway 
  // const subkey = 'changethis'
  //replace the gwhost value with the hostname of the api gateway 

  const gwhost = '172.31.25.74:9980';
  const email = `nn0${__VU}@noname.net`;
  
    let tokenfor = { email : email };
    let JWT = encode(tokenfor, `secret${__VU}`);
   // console.log("encoded", JWT);

  const params = { headers: { 'Ocp-Apim-Subscription-Key':'mockapikeythisapihasnogwapim', 'Content-Type': 'application/json', 'Authorization':'Bearer '+JWT } };

  let res = http.get('http://'+gwhost+'/image/jpeg', params);

  check(res, { 'status was 200': (r) => r.status == 200 });
  // console.log(JSON.stringify(res));
  sleep(1);
}
