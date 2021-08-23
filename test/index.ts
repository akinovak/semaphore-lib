import { Identity, genIdentity, genExternalNullifier, IncrementalQuinTree, 
    createTree, genSignalHash, genMsg, signMsg, verifySignature, EdDSASignature, genNullifierHash,verifyProof, genIdentityCommitment, IProof, genProof } from '../src/index';

// 13267838603087533987148760947767721474645530749940686599003358955365026582253n

import * as ethers from 'ethers';
import * as path from 'path';
import * as fs from 'fs';

async function run() {

    const tree: IncrementalQuinTree = createTree(20, BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')])), 5);
    const leafIndex = 3;
    const idCommitments: Array<any> = [];

    for (let i=0; i<leafIndex;i++) {
      const tmpIdentity: Identity = genIdentity();
      const tmpCommitment: any = genIdentityCommitment(tmpIdentity);
      idCommitments.push(tmpCommitment);
      tree.insert(tmpCommitment);
    }

    const identity: Identity = genIdentity();
    const externalNullifier = genExternalNullifier("voting_1");
    const signal: string = '0x111';
    const signalHash: BigInt = genSignalHash(signal);
    const msg: string = genMsg(externalNullifier, signalHash);
    const signature: EdDSASignature = signMsg(identity.keypair.privKey, msg);
    const nullifiersHash: BigInt = genNullifierHash(externalNullifier, identity, 20);
    const verified: boolean = verifySignature(msg, signature, identity.keypair.pubKey);
    console.log('verified signature', verified);
    const identityCommitment: any = genIdentityCommitment(identity);

    // const vKey: string = loadVkey();
    const vkeyPath: string = path.join('./zkeyFiles', 'verification_key.json');
    const vKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

    tree.insert(identityCommitment);

    const wasmFilePath: string = path.join('./zkeyFiles', 'semaphore.wasm');
    const finalZkeyPath: string = path.join('./zkeyFiles', 'semaphore_final.zkey');


    const fullProof: IProof = await genProof(identity, signature, signalHash, externalNullifier, tree, leafIndex, wasmFilePath, finalZkeyPath);
    const res = await verifyProof(vKey, fullProof);
    console.log(res);

}


(async () => {
    await run();
    process.exit(0);
})();