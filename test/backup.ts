// import { Identity, genIdentity, genExternalNullifier, genSignalHash, genMsg, signMsg, verifySignature, EdDSASignature, genNullifierHash,verifyProof, genIdentityCommitment, genProof, IWitnessData } from '../src/index';
// import * as ethers from 'ethers';
// import * as path from 'path';
// import * as fs from 'fs';
// const snarkjs = require('snarkjs');

// const ZERO_VALUE = BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')]));

// async function run() {
//     const leafIndex = 3;
//     const idCommitments: Array<any> = [];

//     for (let i=0; i<leafIndex;i++) {
//       const tmpIdentity: Identity = genIdentity();
//       const tmpCommitment: any = genIdentityCommitment(tmpIdentity, 'poseidon', 'fast');
//       idCommitments.push(tmpCommitment);
//     }

//     const identity: Identity = genIdentity();
//     const externalNullifier = genExternalNullifier("voting_1");
//     const signal: string = '0x111';
//     const signalHash: BigInt = genSignalHash(signal);
//     const msg: string = genMsg(externalNullifier, signalHash);
//     const signature: EdDSASignature = signMsg(identity.keypair.privKey, msg);
//     const nullifierHash: BigInt = genNullifierHash(externalNullifier, identity.identityNullifier, 20);
//     const identityCommitment: BigInt = genIdentityCommitment(identity, 'poseidon', 'fast');
//     idCommitments.push(identityCommitment);

//     const vkeyPath: string = path.join('./zkeyFiles', 'verification_key.json');
//     const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

//     const wasmFilePath: string = path.join('./zkeyFiles', 'semaphore.wasm');
//     const finalZkeyPath: string = path.join('./zkeyFiles', 'semaphore_final.zkey');

//     const witnessData: IWitnessData = await genProof(identity, signature, signalHash, idCommitments, externalNullifier, 20, ZERO_VALUE, 5, wasmFilePath, finalZkeyPath);
//     const pubSignals = [witnessData.root, nullifierHash, signalHash, externalNullifier];

//     const res = await snarkjs.groth16.verify(vKey, pubSignals, witnessData.fullProof.proof);
//     if (res === true) {
//         console.log("Verification OK");
//     } else {
//         console.log("Invalid proof");
//     }
// }


// (async () => {
//     await run();
//     process.exit(0);
// })();


