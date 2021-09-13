import * as ethers from 'ethers';
import { FastSemaphore, OrdinarySemaphore, Identity } from '../src/index';
import * as path from 'path';
import * as fs from 'fs';
import { IWitnessData } from '../src/types';
const snarkjs = require('snarkjs');

const ZERO_VALUE = BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')]));

async function testFastSemaphore() {
    const leafIndex = 3;
    const idCommitments: Array<any> = [];

    FastSemaphore.setHasher('poseidon');

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity = FastSemaphore.genIdentity();
      const tmpCommitment: any = FastSemaphore.genIdentityCommitment(tmpIdentity);
      idCommitments.push(tmpCommitment);
    }

    const identity: Identity = FastSemaphore.genIdentity();
    const externalNullifier: string = FastSemaphore.genExternalNullifier("voting_1");
    const signal: string = '0x111';
    const nullifierHash: BigInt = FastSemaphore.genNullifierHash(externalNullifier, identity.identityNullifier, 20);
    const identityCommitment: BigInt = FastSemaphore.genIdentityCommitment(identity);
    idCommitments.push(identityCommitment);

    const vkeyPath: string = path.join('./fast-zkeyFiles', 'verification_key.json');
    const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

    const wasmFilePath: string = path.join('./fast-zkeyFiles', 'semaphore.wasm');
    const finalZkeyPath: string = path.join('./fast-zkeyFiles', 'semaphore_final.zkey');

    const witnessData: IWitnessData = await FastSemaphore.genProofFromIdentityCommitments(identity, externalNullifier, signal, wasmFilePath, finalZkeyPath, 
        idCommitments, 20, ZERO_VALUE, 5);
    const pubSignals = [witnessData.root, nullifierHash, FastSemaphore.genSignalHash(signal), externalNullifier];

    const res = await snarkjs.groth16.verify(vKey, pubSignals, witnessData.fullProof.proof);
    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
}

async function testOrdinarySemaphore() {
    const leafIndex = 3;
    const idCommitments: Array<any> = [];

    OrdinarySemaphore.setHasher('pedersen');

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity = OrdinarySemaphore.genIdentity();
      const tmpCommitment: any = OrdinarySemaphore.genIdentityCommitment(tmpIdentity);
      idCommitments.push(tmpCommitment);
    }

    const identity = OrdinarySemaphore.genIdentity();
    const externalNullifier = OrdinarySemaphore.genExternalNullifier("voting_1");
    const signal: string = '0x111';
    const nullifierHash: BigInt = OrdinarySemaphore.genNullifierHash(externalNullifier, identity.identityNullifier, 20);
    const identityCommitment: BigInt = OrdinarySemaphore.genIdentityCommitment(identity);
    idCommitments.push(identityCommitment);

    const vkeyPath: string = path.join('./ordinary-zkeyFiles', 'verification_key.json');
    const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

    const wasmFilePath: string = path.join('./ordinary-zkeyFiles', 'semaphore.wasm');
    const finalZkeyPath: string = path.join('./ordinary-zkeyFiles', 'semaphore_final.zkey');

    const witnessData: IWitnessData = await OrdinarySemaphore.genProofFromIdentityCommitments(identity, externalNullifier, signal, wasmFilePath, finalZkeyPath, 
        idCommitments, 20, ZERO_VALUE, 5);
    const pubSignals = [witnessData.root, nullifierHash, OrdinarySemaphore.genSignalHash(signal), externalNullifier];

    const res = await snarkjs.groth16.verify(vKey, pubSignals, witnessData.fullProof.proof);
    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
}



(async () => {
    await testFastSemaphore();
    await testOrdinarySemaphore();
    process.exit(0);
})();
